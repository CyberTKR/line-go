package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	lineclient "github.com/CyberTKR/line-go/client"
)

type Engine struct {
	Store      *Store
	Logger     *log.Logger
	mu         sync.Mutex
	seen       map[string]time.Time
	clients    map[string]*lineclient.Client
	kinds      map[string]string
	members    map[string]map[string]bool
	health     *healthPool
	audit      map[string][]auditEvent
	spam       map[string]*spamState
	war        map[string]*warRuntime
	fleetSync  map[string]bool
	fleetDirty map[string]bool
	pending    map[string]map[string]time.Time
	defended   map[string]time.Time
	expected   int
	reconciled bool
}

func (e *Engine) SetExpectedClients(count int) {
	e.mu.Lock()
	e.expected = count
	e.mu.Unlock()
}

type auditEvent struct {
	At      int64
	Action  string
	Actor   string
	Targets []string
}

type spamState struct {
	Events []time.Time
	Warned time.Time
}

func NewEngine(store *Store, logger *log.Logger) *Engine {
	if logger == nil {
		logger = log.Default()
	}
	return &Engine{Store: store, Logger: logger, seen: make(map[string]time.Time), clients: make(map[string]*lineclient.Client), kinds: make(map[string]string), members: make(map[string]map[string]bool), health: newHealthPool(), audit: make(map[string][]auditEvent), spam: make(map[string]*spamState), war: make(map[string]*warRuntime), fleetSync: make(map[string]bool), fleetDirty: make(map[string]bool), pending: make(map[string]map[string]time.Time), defended: make(map[string]time.Time)}
}

func (e *Engine) RegisterClient(ctx context.Context, account, kind string, client *lineclient.Client) error {
	if err := e.Store.RegisterBot(client.Session.MID); err != nil {
		return err
	}
	e.mu.Lock()
	existing := make([]*lineclient.Client, 0, len(e.clients))
	for _, other := range e.clients {
		existing = append(existing, other)
	}
	e.clients[client.Session.MID] = client
	e.health.register(client.Session.MID)
	if kind == "reserve" {
		e.kinds[client.Session.MID] = "reserve"
	} else {
		e.kinds[client.Session.MID] = "primary"
	}
	e.mu.Unlock()
	for _, other := range existing {
		for _, pair := range [][2]*lineclient.Client{{client, other}, {other, client}} {
			added, err := pair[0].EnsureFriend(ctx, pair[1].Session.MID)
			if err != nil {
				return fmt.Errorf("bot friend sync %s -> %s: %w", pair[0].Session.MID, pair[1].Session.MID, err)
			}
			if added {
				e.Logger.Printf("guard bot friend added account=%s from=%s target=%s", account, pair[0].Session.MID, pair[1].Session.MID)
			}
		}
	}
	e.mu.Lock()
	ready := !e.reconciled && e.expected > 0 && len(e.clients) >= e.expected
	if ready {
		e.reconciled = true
	}
	e.mu.Unlock()
	if ready {
		if err := e.ReconcileStartup(ctx); err != nil {
			return fmt.Errorf("startup reconciliation: %w", err)
		}
	}
	return nil
}

func (e *Engine) ReconcileStartup(ctx context.Context) error {
	e.mu.Lock()
	clients := make([]*lineclient.Client, 0, len(e.clients))
	for _, current := range e.clients {
		clients = append(clients, current)
	}
	e.mu.Unlock()
	type view struct {
		client *lineclient.Client
		chat   lineclient.Chat
	}
	groups := make(map[string][]view)
	for _, current := range clients {
		chats, err := current.GetChats(ctx, nil)
		if err != nil {
			e.Logger.Printf("startup chat scan failed bot=%s: %v", current.Session.MID, err)
			continue
		}
		for _, chat := range chats {
			if chat.MID == "" || chat.MID[0] != 'c' {
				continue
			}
			groups[chat.MID] = append(groups[chat.MID], view{client: current, chat: chat})
			e.setMember(chat.MID, current.Session.MID, contains(chat.Members, current.Session.MID))
		}
	}
	for group, views := range groups {
		memberSet := make(map[string]bool)
		for _, current := range views {
			for _, mid := range current.chat.Members {
				memberSet[mid] = true
			}
		}
		var active []*lineclient.Client
		for _, current := range clients {
			if memberSet[current.Session.MID] {
				active = append(active, current)
			}
		}
		if len(active) == 0 {
			_, reserves := e.Store.ReservePlan(group)
			for _, reserveMID := range reserves {
				for _, current := range views {
					if current.client.Session.MID == reserveMID && !memberSet[reserveMID] {
						if err := current.client.AcceptChatInvitation(ctx, group); err == nil {
							e.setMember(group, reserveMID, true)
							active = append(active, current.client)
						}
					}
				}
			}
		}
		if len(active) == 0 {
			continue
		}
		leader := e.health.rank(active)[0]
		for mid := range memberSet {
			if e.Store.IsBlacklisted(mid) {
				if err := e.kick(ctx, leader, group, mid); err != nil {
					e.Logger.Printf("startup blacklist sweep failed group=%s target=%s: %v", group, mid, err)
				}
			}
		}
		var missing []string
		_, groupReserves := e.Store.ReservePlan(group)
		e.mu.Lock()
		for mid, kind := range e.kinds {
			if kind == "primary" && !memberSet[mid] && !contains(groupReserves, mid) {
				missing = append(missing, mid)
			}
		}
		e.mu.Unlock()
		if len(missing) > 0 {
			if err := e.admitPrimaryFleetByGroupTicket(ctx, group, leader); err != nil {
				e.Logger.Printf("startup missing bot ticket rollout failed group=%s count=%d: %v", group, len(missing), err)
			}
		}
		e.Logger.Printf("startup reconciled group=%s active_bots=%d missing_bots=%d members=%d", group, len(active), len(missing), len(memberSet))
	}
	return nil
}

func (e *Engine) Handle(ctx context.Context, account string, operation lineclient.Operation, client *lineclient.Client) error {
	if err := e.Store.RegisterBot(client.Session.MID); err != nil {
		return err
	}
	e.Logger.Printf("guard op account=%s revision=%d type=%d name=%s", account, operation.Revision, operation.Type, operation.TypeName)
	e.observeMembership(operation, client.Session.MID)
	e.observeAudit(operation)
	if operation.Param1 != "" {
		e.observeWarAuto(operation.Param1)
	}
	switch operation.Type {
	case 26:
		return e.handleMessage(ctx, account, operation, client)
	case 55:
		return e.handleRead(operation)
	case 60:
		return e.handleJoin(ctx, operation, client)
	case 124:
		return e.handleInvitation(ctx, operation, client)
	case 126:
		return e.handleCancellation(ctx, operation, client)
	case 122:
		return e.handleChatUpdate(ctx, operation, client)
	case 133:
		return e.handleKick(ctx, operation, client)
	default:
		return nil
	}
}

func (e *Engine) observeAudit(operation lineclient.Operation) {
	var action, group, actor string
	var targets []string
	switch operation.Type {
	case 60:
		action, group, actor = "join", operation.Param1, operation.Param2
		if actor == "" {
			actor = operation.Param3
		}
		targets = []string{actor}
	case 124:
		action, group, actor, targets = "invite", operation.Param1, operation.Param2, splitMIDs(operation.Param3)
	case 126:
		action, group, actor, targets = "cancel", operation.Param1, operation.Param2, splitMIDs(operation.Param3)
	case 133:
		action, group, actor, targets = "kick", operation.Param1, operation.Param2, splitMIDs(operation.Param3)
	default:
		return
	}
	if group == "" || actor == "" || e.duplicate(fmt.Sprintf("audit:%d:%d:%s:%s", operation.Type, operation.CreatedTime, group, actor)) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	items := append(e.audit[group], auditEvent{At: operation.CreatedTime, Action: action, Actor: actor, Targets: append([]string(nil), targets...)})
	if len(items) > 200 {
		items = append([]auditEvent(nil), items[len(items)-200:]...)
	}
	e.audit[group] = items
}

func (e *Engine) handleRead(operation lineclient.Operation) error {
	group, reader := operation.Param1, operation.Param2
	if group == "" || reader == "" || e.Store.IsBot(reader) {
		return nil
	}
	if e.Store.RecordReader(group, reader) {
		e.Logger.Printf("guard lurk reader group=%s mid=%s", group, reader)
	}
	return nil
}

func (e *Engine) handleInvitation(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	group, inviter := operation.Param1, operation.Param2
	invited := splitMIDs(operation.Param3)
	if contains(invited, client.Session.MID) {
		e.clearPendingInvite(group, client.Session.MID)
		_, selected := e.Store.ReservePlan(group)
		if contains(selected, client.Session.MID) && e.primaryCount(group) > 0 {
			e.Logger.Printf("reserve waiting account=%s group=%s", client.Session.MID, group)
			return nil
		}
		created, err := e.Store.BootstrapCreator(inviter)
		if err != nil {
			return err
		}
		if err := client.AcceptChatInvitation(ctx, group); err != nil {
			e.reconcilePrimaryFleetAsync(group, "accept failed")
			return fmt.Errorf("bot invitation could not be accepted: %w", err)
		}
		e.setMember(group, client.Session.MID, true)
		e.Logger.Printf("guard account=%s group=%s invitation accepted inviter=%s creator_bootstrap=%t", client.Session.MID, group, inviter, created)
		if !e.Store.IsBot(inviter) && e.Store.Role(group, inviter) == RoleCreator {
			if err := e.admitPrimaryFleetByGroupTicket(ctx, group, client); err != nil {
				e.Logger.Printf("guard ticket rollout failed group=%s inviter=%s: %v", group, inviter, err)
				e.reconcilePrimaryFleetAsync(group, "ticket rollout fallback")
			}
		}
		if created {
			return e.reply(ctx, client, group, "Creator registered: "+inviter)
		}
		return nil
	}
	if e.Store.Creator() == "" || e.duplicate(eventKey(operation)) {
		return nil
	}
	war, warActive := e.warActive(group)
	if !e.Store.Protection(group).Invite && !warActive && !war.Locked {
		return nil
	}
	actorRole := e.Store.Role(group, inviter)
	allowed := e.Store.IsBot(inviter) || e.Store.CanInvite(group, inviter)
	if actorRole == RoleGAdmin {
		for _, target := range invited {
			if e.Store.IsBot(target) {
				allowed = false
				break
			}
		}
	}
	if allowed {
		var blocked []string
		for _, target := range invited {
			if e.Store.IsBlacklisted(target) {
				blocked = append(blocked, target)
			}
		}
		if len(blocked) == 0 {
			return nil
		}
		protector := e.protectorFor(group, "", client)
		if protector == nil {
			return fmt.Errorf("no primary bot is in the group to cancel invitations")
		}
		return e.cancel(ctx, protector, group, blocked...)
	}
	if warActive {
		e.addWarRisk(group, inviter, 3)
	}
	protector := e.protectorFor(group, "", client)
	if protector == nil {
		return fmt.Errorf("no active bot is available to stop the unauthorized invitation")
	}
	if err := e.cancel(ctx, protector, group, invited...); err != nil {
		e.Logger.Printf("guard cancel unauthorized invitation failed group=%s: %v", group, err)
	}
	if e.Store.CanKick(group, e.Store.Creator(), inviter) {
		if err := e.ejectAndBlacklist(ctx, protector, group, inviter); err != nil {
			return fmt.Errorf("unauthorized inviter could not be removed: %w", err)
		}
	}
	return nil
}

func (e *Engine) admitPrimaryFleetByGroupTicket(ctx context.Context, group string, leader *lineclient.Client) (resultErr error) {
	chats, err := leader.GetChats(ctx, []string{group})
	if err != nil || len(chats) != 1 {
		return fmt.Errorf("ticket rollout could not retrieve the member list: %w", err)
	}
	present := make(map[string]bool, len(chats[0].Members))
	for _, mid := range chats[0].Members {
		present[mid] = true
	}
	e.mu.Lock()
	var joining []*lineclient.Client
	for mid, current := range e.clients {
		if current != nil && mid != leader.Session.MID && e.kinds[mid] == "primary" && !present[mid] {
			joining = append(joining, current)
		}
	}
	e.mu.Unlock()
	if len(joining) == 0 {
		return nil
	}
	sort.Slice(joining, func(i, j int) bool { return joining[i].Session.MID < joining[j].Session.MID })
	ticketID, err := leader.ReissueChatTicket(ctx, group)
	if err != nil {
		return fmt.Errorf("group ticket could not be generated: %w", err)
	}
	if err := leader.OpenChatTicket(ctx, group); err != nil {
		return fmt.Errorf("group ticket joining could not be enabled: %w", err)
	}
	defer func() {
		if closeErr := leader.CloseChatTicket(context.Background(), group); closeErr != nil {
			e.Logger.Printf("guard group ticket close failed leader=%s group=%s: %v", leader.Session.MID, group, closeErr)
			if resultErr == nil {
				resultErr = closeErr
			}
		}
	}()
	joined := 0
	for index, current := range joining {
		if index > 0 {
			timer := time.NewTimer(150 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
		if err := current.AcceptChatInvitationByTicket(ctx, group, ticketID); err != nil {
			e.Logger.Printf("guard ticket join failed group=%s bot=%s: %v", group, current.Session.MID, err)
			continue
		}
		e.setMember(group, current.Session.MID, true)
		joined++
	}
	if joined != len(joining) {
		return fmt.Errorf("%d/%d primary bots joined by ticket", joined, len(joining))
	}
	e.Logger.Printf("guard primary ticket rollout leader=%s group=%s joined=%d", leader.Session.MID, group, joined)
	return nil
}

func (e *Engine) handleKick(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	group, actor, target := operation.Param1, operation.Param2, operation.Param3
	if group == "" || actor == "" || target == "" || e.Store.Creator() == "" {
		return nil
	}
	war, warActive := e.warActive(group)
	if warActive && !e.warProtected(group, actor) {
		e.addWarRisk(group, actor, 5)
	}
	if e.Store.IsBot(target) {
		if e.duplicate("bot-defense:" + eventKey(operation) + ":" + client.Session.MID) {
			return nil
		}
		if !e.Store.IsBot(actor) && client.Session.MID != target && e.isPrimary(client.Session.MID) {
			defenseKey := fmt.Sprintf("%d:%s:%s", operation.CreatedTime, group, actor)
			position, selected := e.defensePosition(group, target, client.Session.MID)
			if selected && position > 0 {
				timer := time.NewTimer(time.Duration(position) * 20 * time.Millisecond)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					selected = false
				}
			}
			if selected && !e.defenseCompleted(defenseKey, false) {
				if err := e.fastBotDefenseKick(ctx, client, group, actor); err != nil {
					e.Logger.Printf("guard fast bot defense failed defender=%s group=%s actor=%s: %v", client.Session.MID, group, actor, err)
				} else {
					e.defenseCompleted(defenseKey, true)
				}
			}
		}
		if e.isPrimary(target) && e.primaryCount(group) == 0 {
			if !warActive {
				e.launchRecoveryAsync(group)
			}
			return nil
		}
		e.reconcilePrimaryFleetAsync(group, "op133")
		return nil
	}
	if e.duplicate(eventKey(operation)) {
		return nil
	}
	protector := e.protectorFor(group, target, client)
	targetRole, actorRole := e.Store.Role(group, target), e.Store.Role(group, actor)
	if targetRole >= RoleOwner {
		if actorRole == RoleCreator || e.Store.IsBot(actor) {
			return nil
		}
		if protector == nil {
			return fmt.Errorf("no active bot is available to reinvite the privileged user")
		}
		if actorRole == RoleUser && e.Store.Protection(group).Kick {
			if err := e.ejectAndBlacklist(ctx, protector, group, actor); err != nil {
				e.Logger.Printf("guard privileged defense kick failed group=%s actor=%s: %v", group, actor, err)
			}
		}
		return e.reinvitePrivileged(ctx, protector, group, target)
	}
	if e.Store.IsBot(actor) {
		return nil
	}
	if e.Store.CanKick(group, actor, target) || e.Store.Role(group, actor) != RoleUser || (!e.Store.Protection(group).Kick && !(warActive && war.Level >= 2)) {
		return nil
	}
	if protector == nil {
		return fmt.Errorf("no active bot is available to remove the attacker")
	}
	if err := e.ejectAndBlacklist(ctx, protector, group, actor); err != nil {
		return fmt.Errorf("kick protection could not remove the attacker: %w", err)
	}
	return nil
}

func (e *Engine) fastBotDefenseKick(ctx context.Context, client *lineclient.Client, group, actor string) error {
	if !e.member(group, client.Session.MID) {
		return fmt.Errorf("fast defense skipped: bot has no local membership")
	}
	persisted := make(chan error, 1)
	go func() { persisted <- e.Store.AutoBlacklist(group, actor) }()
	err := client.KickFromChat(ctx, group, actor)
	e.health.record(client.Session.MID, "kick", err)
	e.recordWarAction(group, "kick", err)
	stateErr := <-persisted
	if err != nil {
		return err
	}
	return stateErr
}

func (e *Engine) defensePosition(group, excluded, current string) (int, bool) {
	e.mu.Lock()
	var candidates []*lineclient.Client
	for mid, candidate := range e.clients {
		if candidate != nil && mid != excluded && e.kinds[mid] == "primary" && e.members[group][mid] {
			candidates = append(candidates, candidate)
		}
	}
	e.mu.Unlock()
	for index, candidate := range e.health.rank(candidates) {
		if candidate.Session.MID == current {
			return index, true
		}
	}
	return 0, false
}

func (e *Engine) defenseCompleted(key string, mark bool) bool {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for current, expires := range e.defended {
		if now.After(expires) {
			delete(e.defended, current)
		}
	}
	if mark {
		e.defended[key] = now.Add(10 * time.Second)
		return true
	}
	return now.Before(e.defended[key])
}

func (e *Engine) reinvitePrivileged(ctx context.Context, protector *lineclient.Client, group, target string) error {
	if _, err := protector.EnsureFriend(ctx, target); err != nil {
		e.Logger.Printf("guard privileged friend failed protector=%s target=%s: %v", protector.Session.MID, target, err)
	}
	if err := e.invite(ctx, protector, group, target); err != nil {
		return fmt.Errorf("privileged user could not be reinvited: %w", err)
	}
	e.Logger.Printf("guard privileged reinvited protector=%s target=%s group=%s", protector.Session.MID, target, group)
	return nil
}

func (e *Engine) protectorFor(group, excluded string, fallback *lineclient.Client) *lineclient.Client {
	e.mu.Lock()
	defer e.mu.Unlock()
	var mids []string
	for mid, current := range e.clients {
		if mid != excluded && e.members[group][mid] && current != nil {
			mids = append(mids, mid)
		}
	}
	sort.Strings(mids)
	if len(mids) > 0 {
		candidates := make([]*lineclient.Client, 0, len(mids))
		for _, mid := range mids {
			candidates = append(candidates, e.clients[mid])
		}
		return e.health.rank(candidates)[0]
	}
	if fallback != nil && fallback.Session.MID != excluded {
		return fallback
	}
	return nil
}

func (e *Engine) handleCancellation(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	group, actor, target := operation.Param1, operation.Param2, operation.Param3
	targets := splitMIDs(target)
	_, warActive := e.warActive(group)
	if group == "" || actor == "" || target == "" || e.duplicate(eventKey(operation)) {
		return nil
	}
	botCancelled := false
	for _, mid := range targets {
		if e.isPrimary(mid) {
			botCancelled = true
			e.setMember(group, mid, false)
			e.clearPendingInvite(group, mid)
		}
	}
	if botCancelled {
		e.reconcilePrimaryFleetAsync(group, "op126")
	}
	if !e.Store.Protection(group).Cancel && !warActive {
		return nil
	}
	if e.Store.IsBot(actor) || e.Store.Role(group, actor) != RoleUser {
		return nil
	}
	if warActive {
		e.addWarRisk(group, actor, 3)
	}
	protector := e.protectorFor(group, target, client)
	if protector != nil && !e.Store.IsBot(actor) {
		_ = e.ejectAndBlacklist(ctx, protector, group, actor)
	}
	return nil
}

func (e *Engine) handleChatUpdate(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	group, actor, attribute := operation.Param1, operation.Param2, operation.Param3
	war, warActive := e.warActive(group)
	if group == "" || actor == "" || attribute != "4" || (!e.Store.Protection(group).QR && !warActive && !war.Locked) || e.duplicate(eventKey(operation)) {
		return nil
	}
	if e.Store.IsBot(actor) || e.Store.Role(group, actor) != RoleUser {
		return nil
	}
	if warActive {
		e.addWarRisk(group, actor, 4)
	}
	protector := e.protectorFor(group, "", client)
	if protector == nil {
		return fmt.Errorf("no bot is available to enforce QR protection")
	}
	if err := protector.CloseChatTicket(ctx, group); err != nil {
		e.recordWarAction(group, "qr", err)
		return fmt.Errorf("group QR could not be closed: %w", err)
	}
	e.recordWarAction(group, "qr", nil)
	if err := e.ejectAndBlacklist(ctx, protector, group, actor); err != nil {
		return fmt.Errorf("the user who opened QR could not be removed: %w", err)
	}
	return nil
}

func (e *Engine) ejectAndBlacklist(ctx context.Context, client *lineclient.Client, group, actor string) error {
	persisted := make(chan error, 1)
	go func() {
		persisted <- e.Store.AutoBlacklist(group, actor)
	}()
	kickErr := e.kick(ctx, client, group, actor)
	if kickErr != nil {
		e.mu.Lock()
		var alternatives []*lineclient.Client
		for mid, candidate := range e.clients {
			if candidate != nil && mid != client.Session.MID && e.members[group][mid] {
				alternatives = append(alternatives, candidate)
			}
		}
		e.mu.Unlock()
		for _, candidate := range e.health.rank(alternatives) {
			if retryErr := e.kick(ctx, candidate, group, actor); retryErr == nil {
				kickErr = nil
				break
			} else {
				kickErr = retryErr
			}
		}
	}
	stateErr := <-persisted
	if stateErr != nil {
		e.Logger.Printf("guard blacklist persistence failed group=%s actor=%s: %v", group, actor, stateErr)
	}
	if kickErr != nil {
		return kickErr
	}
	return stateErr
}

func (e *Engine) reinviteBot(ctx context.Context, group, target string) error {
	if !e.isPrimary(target) {
		return fmt.Errorf("non-primary accounts are not eligible for automatic recovery")
	}
	return e.reconcilePrimaryFleet(ctx, group)
}

func (e *Engine) reconcilePrimaryFleetAsync(group, reason string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := e.reconcilePrimaryFleet(ctx, group); err != nil {
			e.Logger.Printf("guard fleet recovery failed reason=%s group=%s: %v", reason, group, err)
		}
	}()
}

func (e *Engine) launchRecoveryAsync(group string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if err := e.launchRecovery(ctx, group); err != nil {
			e.Logger.Printf("guard reserve recovery failed group=%s: %v", group, err)
		}
	}()
}

func (e *Engine) reconcilePrimaryFleet(ctx context.Context, group string) error {
	e.mu.Lock()
	if e.fleetSync[group] {
		e.fleetDirty[group] = true
		e.mu.Unlock()
		return nil
	}
	e.fleetSync[group] = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.fleetSync, group)
		delete(e.fleetDirty, group)
		e.mu.Unlock()
	}()

	var lastErr error
	for pass := 0; pass < 4; pass++ {
		e.mu.Lock()
		delete(e.fleetDirty, group)
		var candidates []*lineclient.Client
		for mid, candidate := range e.clients {
			if candidate != nil && e.kinds[mid] == "primary" && e.members[group][mid] {
				candidates = append(candidates, candidate)
			}
		}
		e.mu.Unlock()
		if len(candidates) == 0 {
			return fmt.Errorf("no primary guard remains in the group; ghost accounts are not used during war")
		}

		ranked := e.health.rank(candidates)
		e.mu.Lock()
		var missing []string
		for mid, kind := range e.kinds {
			if kind == "primary" && !e.members[group][mid] && !e.pendingInviteLocked(group, mid, time.Now()) {
				missing = append(missing, mid)
			}
		}
		e.mu.Unlock()
		if len(missing) > 0 {
			sort.Strings(missing)
			for targetIndex, target := range missing {
				invited := false
				for attempt := 0; attempt < len(ranked); attempt++ {
					protector := ranked[(targetIndex+attempt)%len(ranked)]
					if protector.Session.MID == target {
						continue
					}
					requestCtx, cancel := context.WithTimeout(ctx, 850*time.Millisecond)
					err := protector.InviteIntoChat(requestCtx, group, target)
					cancel()
					e.health.record(protector.Session.MID, "invite", err)
					e.recordWarAction(group, "invite", err)
					if err == nil {
						e.markPendingInvite(group, target)
						e.Logger.Printf("guard primary recovery invite protector=%s group=%s target=%s", protector.Session.MID, group, target)
						e.recordWarAction(group, "rescue", nil)
						lastErr, invited = nil, true
						break
					}
					lastErr = err
					if strings.Contains(strings.ToLower(err.Error()), "not a member") {
						e.setMember(group, protector.Session.MID, false)
					}
				}
				if !invited {
					e.Logger.Printf("guard primary recovery exhausted group=%s target=%s: %v", group, target, lastErr)
				}
			}
		}
		e.mu.Lock()
		dirty := e.fleetDirty[group]
		e.mu.Unlock()
		if !dirty {
			return lastErr
		}
	}
	return lastErr
}

func (e *Engine) handleJoin(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	group, joined := operation.Param1, operation.Param2
	if joined == "" {
		joined = operation.Param3
	}
	if group == "" || joined == "" || !e.Store.IsBlacklisted(joined) || e.duplicate(eventKey(operation)) {
		if group != "" && joined != "" {
			if err := e.warJoinAction(ctx, client, group, joined); err != nil {
				return err
			}
		}
		if group != "" && e.isPrimary(joined) && !e.isGroupReserve(group, joined) {
			return e.parkReserves(ctx, group, client)
		}
		return nil
	}
	return e.kick(ctx, client, group, joined)
}

func (e *Engine) configureReserves(ctx context.Context, client *lineclient.Client, group, actor string, count int) (string, error) {
	_, oldSelected := e.Store.ReservePlan(group)
	chats, err := client.GetChats(ctx, []string{group})
	if err != nil || len(chats) != 1 {
		return "", fmt.Errorf("group members could not be retrieved for ghost mode: %w", err)
	}
	present := make(map[string]bool, len(chats[0].Members))
	for _, mid := range chats[0].Members {
		present[mid] = true
	}
	e.mu.Lock()
	var candidates []string
	for _, mid := range oldSelected {
		if mid != client.Session.MID && e.clients[mid] != nil {
			candidates = append(candidates, mid)
		}
	}
	for mid := range e.clients {
		if mid != client.Session.MID && present[mid] && !contains(candidates, mid) {
			candidates = append(candidates, mid)
		}
	}
	e.mu.Unlock()
	if len(oldSelected) < len(candidates) {
		sort.Strings(candidates[len(oldSelected):])
	}
	if len(candidates) < count {
		return "", fmt.Errorf("%d ghost accounts require at least %d other bots inside; ready=%d", count, count, len(candidates))
	}
	selected := candidates[:count]
	if err := e.Store.SetReservePlan(group, actor, count, selected); err != nil {
		return "", err
	}
	for _, mid := range oldSelected {
		if contains(selected, mid) {
			continue
		}
		e.mu.Lock()
		previous := e.clients[mid]
		e.mu.Unlock()
		if previous != nil {
			if err := previous.AcceptChatInvitation(ctx, group); err != nil {
				e.Logger.Printf("former ghost rejoin failed group=%s mid=%s: %v", group, mid, err)
			}
		}
	}
	if count == 0 {
		return "Ghost standby mode disabled", nil
	}
	for _, mid := range selected {
		e.mu.Lock()
		reserve := e.clients[mid]
		e.mu.Unlock()
		if reserve == nil {
			continue
		}
		if present[mid] {
			if err := reserve.LeaveChat(ctx, group); err != nil {
				return "", fmt.Errorf("reserve account could not leave the group %s: %w", mid, err)
			}
		}
		if !contains(oldSelected, mid) {
			if err := e.invite(ctx, client, group, mid); err != nil {
				e.Logger.Printf("reserve invite may already be pending group=%s mid=%s: %v", group, mid, err)
			}
		}
	}
	return fmt.Sprintf("%d ghost accounts are waiting in invitations for recovery", count), nil
}

func (e *Engine) launchRecovery(ctx context.Context, group string) error {
	count, selected := e.Store.ReservePlan(group)
	if count == 0 || len(selected) == 0 {
		return fmt.Errorf("no primary bot remains in the group and no ghost plan is configured")
	}
	if e.duplicate("recovery:" + group) {
		return nil
	}
	var rescuer *lineclient.Client
	for _, mid := range selected {
		e.mu.Lock()
		reserve := e.clients[mid]
		e.mu.Unlock()
		if reserve == nil {
			continue
		}
		if err := reserve.AcceptChatInvitation(ctx, group); err != nil {
			e.Logger.Printf("reserve join failed group=%s mid=%s: %v", group, mid, err)
			continue
		}
		e.setMember(group, mid, true)
		if rescuer == nil {
			rescuer = reserve
		}
	}
	if rescuer == nil {
		return fmt.Errorf("no reserve account could accept the invitation")
	}
	chats, err := rescuer.GetChats(ctx, []string{group})
	if err != nil || len(chats) != 1 {
		return fmt.Errorf("recovery member list could not be retrieved: %w", err)
	}
	for _, member := range chats[0].Members {
		if e.Store.IsBlacklisted(member) {
			if err := e.kick(ctx, rescuer, group, member); err != nil {
				e.Logger.Printf("recovery blacklist removal failed group=%s target=%s: %v", group, member, err)
			}
		}
	}
	e.mu.Lock()
	var primaries []string
	for mid, kind := range e.kinds {
		if kind == "primary" {
			primaries = append(primaries, mid)
		}
	}
	e.mu.Unlock()
	sort.Strings(primaries)
	for _, mid := range primaries {
		_, _ = rescuer.EnsureFriend(ctx, mid)
		if err := e.invite(ctx, rescuer, group, mid); err != nil {
			e.Logger.Printf("recovery primary invite failed group=%s target=%s: %v", group, mid, err)
		}
	}
	e.Logger.Printf("reserve recovery completed group=%s swept_members=%d invited_primary=%d", group, len(chats[0].Members), len(primaries))
	e.recordWarAction(group, "rescue", nil)
	return nil
}

func (e *Engine) parkReserves(ctx context.Context, group string, inviter *lineclient.Client) error {
	_, selected := e.Store.ReservePlan(group)
	if len(selected) == 0 || e.duplicate("park-reserve:"+group) {
		return nil
	}
	for _, mid := range selected {
		e.mu.Lock()
		reserve := e.clients[mid]
		e.mu.Unlock()
		if reserve == nil || !e.member(group, mid) {
			continue
		}
		if err := reserve.LeaveChat(ctx, group); err != nil {
			return err
		}
		e.setMember(group, mid, false)
		if err := e.invite(ctx, inviter, group, mid); err != nil {
			return err
		}
	}
	e.Logger.Printf("reserve pool returned to pending invitations group=%s count=%d", group, len(selected))
	return nil
}

func (e *Engine) observeMembership(operation lineclient.Operation, current string) {
	if operation.Message != nil && operation.Message.ToType == 2 {
		e.setMember(operation.Message.To, current, true)
	}
	switch operation.Type {
	case 60:
		joined := operation.Param2
		if joined == "" {
			joined = operation.Param3
		}
		if e.Store.IsBot(joined) {
			e.setMember(operation.Param1, joined, true)
		}
	case 133:
		if e.Store.IsBot(operation.Param3) {
			e.setMember(operation.Param1, operation.Param3, false)
			e.clearPendingInvite(operation.Param1, operation.Param3)
		}
	}
}

func (e *Engine) setMember(group, mid string, present bool) {
	if group == "" || mid == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.members[group] == nil {
		e.members[group] = make(map[string]bool)
	}
	e.members[group][mid] = present
	if present && e.pending[group] != nil {
		delete(e.pending[group], mid)
	}
}

func (e *Engine) pendingInviteLocked(group, mid string, now time.Time) bool {
	items := e.pending[group]
	if items == nil {
		return false
	}
	expires := items[mid]
	if expires.IsZero() || !now.Before(expires) {
		delete(items, mid)
		return false
	}
	return true
}

func (e *Engine) markPendingInvite(group, mid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending[group] == nil {
		e.pending[group] = make(map[string]time.Time)
	}
	e.pending[group][mid] = time.Now().Add(3 * time.Second)
}

func (e *Engine) clearPendingInvite(group, mid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending[group] != nil {
		delete(e.pending[group], mid)
	}
}

func (e *Engine) member(group, mid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.members[group][mid]
}

func (e *Engine) primaryCount(group string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := 0
	for mid, present := range e.members[group] {
		if present && e.kinds[mid] == "primary" {
			count++
		}
	}
	return count
}

func (e *Engine) isReserve(mid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.kinds[mid] == "reserve"
}

func (e *Engine) isPrimary(mid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.kinds[mid] == "primary"
}

func (e *Engine) isGroupReserve(group, mid string) bool {
	_, selected := e.Store.ReservePlan(group)
	return contains(selected, mid)
}

func (e *Engine) handleMessage(ctx context.Context, account string, operation lineclient.Operation, client *lineclient.Client) error {
	started := time.Now()
	message := operation.Message
	if message == nil || message.ToType != 2 || message.To == "" || message.From == "" || e.Store.Creator() == "" {
		return nil
	}
	if e.Store.IsBot(message.From) {
		return nil
	}
	key := "message:" + message.ID + ":" + client.Session.MID
	if message.ID != "" && e.duplicate(key) {
		return nil
	}
	text, err := client.ResolveMessageText(ctx, message)
	if err != nil {
		e.Logger.Printf("guard decrypt failed account=%s group=%s sender=%s message=%s: %v", account, message.To, message.From, message.ID, err)
		if sendErr := e.reply(ctx, client, message.To, "E2EE key refreshed; send the command again."); sendErr == nil {
			e.Logger.Printf("guard E2EE recovery message sent account=%s group=%s", account, message.To)
			return nil
		} else {
			return fmt.Errorf("message could not be decrypted: %v; E2EE recovery could not be sent: %w", err, sendErr)
		}
	}
	if e.Store.Role(message.To, message.From) == RoleUser {
		if e.duplicate("user-message:" + message.ID) {
			return nil
		}
		if handled, abuseErr := e.handleMessageProtection(ctx, client, message, text); handled || abuseErr != nil {
			return abuseErr
		}
	}
	command, targets := parseConfiguredCommand(text, message.Metadata, e.Store.CommandAliases())
	if command == "" {
		return nil
	}
	if !fanoutCommand(command) && message.ID != "" && e.duplicate("command-action:"+message.ID) {
		return nil
	}
	e.Logger.Printf("guard account=%s group=%s actor=%s role=%s command=%q targets=%d", account, message.To, message.From, e.Store.Role(message.To, message.From), command, len(targets))
	response, err := e.execute(ctx, client, message.To, message.From, command, targets, text, started)
	if err != nil {
		response = "Permission/action error: " + err.Error()
	}
	if response == "" {
		return nil
	}
	return e.reply(ctx, client, message.To, response)
}

func fanoutCommand(command string) bool {
	switch command {
	case "ping", "speed", "sp":
		return true
	default:
		return false
	}
}

func (e *Engine) execute(ctx context.Context, client *lineclient.Client, group, actor, command string, targets []string, rawText string, started time.Time) (string, error) {
	target := ""
	if len(targets) > 0 {
		target = targets[0]
	}
	requireTarget := func() error {
		if target == "" {
			return fmt.Errorf("user mention or MID is required")
		}
		return nil
	}
	if strings.HasPrefix(command, "war ") || command == "leader" {
		if command == "leader" {
			return "", e.sendBotStatus(ctx, client, group, true)
		}
		warCommand := strings.TrimSpace(strings.ToLower(strings.TrimSpace(rawText)))
		return e.executeWar(ctx, client, group, actor, warCommand, target)
	}
	switch command {
	case "ping":
		return "pong", nil
	case "speed", "sp":
		return fmt.Sprintf("speed %.1f ms", float64(time.Since(started).Microseconds())/1000), nil
	case "ticket":
		if e.Store.Role(group, actor) < RoleOwner {
			return "", fmt.Errorf("ticket requires Owner or Creator permission")
		}
		return e.userTicketLinks(ctx)
	case "add me":
		if e.Store.Role(group, actor) < RoleOwner {
			return "", fmt.Errorf("add me requires Owner or Creator permission")
		}
		return e.addMe(ctx, client, group, actor)
	case "lurk on":
		if err := e.Store.SetLurk(group, actor, true); err != nil {
			return "", err
		}
		return "Reader tracking enabled; list cleared.", nil
	case "lurk off":
		_, readers := e.Store.LurkState(group)
		if err := e.Store.SetLurk(group, actor, false); err != nil {
			return "", err
		}
		if len(readers) == 0 {
			return "Reader tracking disabled; list is empty.", nil
		}
		return "", e.sendReaderMentions(ctx, client, group, readers, "Reader tracking disabled. Last readers:")
	case "lurk", "readers":
		_, readers := e.Store.LurkState(group)
		if len(readers) == 0 {
			return "No readers yet.", nil
		}
		return "", e.sendReaderMentions(ctx, client, group, readers, "Readers:")
	case "lurk names":
		enabled, readers := e.Store.LurkState(group)
		return e.formatReaders(ctx, client, enabled, readers)
	case "lurk mention":
		_, readers := e.Store.LurkState(group)
		if len(readers) == 0 {
			return "No readers yet.", nil
		}
		return "", e.sendReaderMentions(ctx, client, group, readers, "Readers:")
	case "protect on", "protect off", "invite protect on", "invite protect off", "cancel protect on", "cancel protect off", "kick protect on", "kick protect off", "qr protect on", "qr protect off", "all protect on", "all protect off", "flood protect on", "flood protect off":
		parts := strings.Fields(command)
		scope, enabled := "all", parts[len(parts)-1] == "on"
		if len(parts) == 3 {
			scope = parts[0]
		}
		if scope == "all" && len(parts) == 3 {
			scope = "mention"
		}
		if err := e.Store.SetProtection(group, actor, scope, enabled); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s protection: %t", scope, enabled), nil
	case "bye":
		if e.Store.Role(group, actor) < RoleOwner {
			return "", fmt.Errorf("bye requires Owner permission")
		}
		if err := e.reply(ctx, client, group, "Guard bots are leaving the group."); err != nil {
			return "", err
		}
		return "", e.leaveBotFleet(ctx, group, client)
	case "ghost 1":
		return e.configureReserves(ctx, client, group, actor, 1)
	case "ghost 2":
		return e.configureReserves(ctx, client, group, actor, 2)
	case "ghost off":
		return e.configureReserves(ctx, client, group, actor, 0)
	case "add creator":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Creator added: " + target, e.Store.AddCreator(actor, target)
	case "del creator":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Creator removed: " + target, e.Store.DelCreator(actor, target)
	case "add owner":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Owner added: " + target, e.Store.AddOwner(actor, target)
	case "del owner":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Owner removed: " + target, e.Store.DelOwner(actor, target)
	case "add admin":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Admin added: " + target, e.Store.AddAdmin(actor, target)
	case "del admin":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Admin removed: " + target, e.Store.DelAdmin(actor, target)
	case "add gadmin":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "GAdmin added: " + target, e.Store.AddGAdmin(group, actor, target)
	case "del gadmin":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "GAdmin removed: " + target, e.Store.DelGAdmin(group, actor, target)
	case "blacklist":
		if target == "" {
			state := e.Store.Snapshot()
			if len(state.Blacklist) == 0 {
				return "Blacklist is empty.", nil
			}
			return "", e.sendMIDMentions(ctx, client, group, "Blacklist:", state.Blacklist, nil)
		}
		if err := e.Store.AddBlacklist(group, actor, target); err != nil {
			return "", err
		}
		if e.Store.CanKick(group, actor, target) {
			if err := e.kick(ctx, client, group, target); err != nil {
				return "Added to blacklist, but kick failed: " + target, err
			}
		}
		return "Added to blacklist: " + target, nil
	case "unban":
		if err := requireTarget(); err != nil {
			return "", err
		}
		return "Removed from blacklist: " + target, e.Store.Unban(group, actor, target)
	case "clear blacklist", "clearban":
		removed, err := e.Store.ClearBlacklist(group, actor)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Blacklist cleared: %d entries removed.", removed), nil
	case "kick":
		if err := requireTarget(); err != nil {
			return "", err
		}
		if e.Store.IsBot(target) || e.Store.Role(group, target) != RoleUser {
			return "", fmt.Errorf("bots and privileged users are permanently protected from kick commands")
		}
		if e.Store.Role(group, actor) < RoleGAdmin || actor == target {
			return "", fmt.Errorf("you cannot remove this user")
		}
		return "User removed: " + target, e.kick(ctx, client, group, target)
	case "kickall":
		return e.kickAll(ctx, client, group, actor)
	case "setcmd kick", "setcmd kickall":
		key := strings.TrimPrefix(command, "setcmd ")
		alias := commandRemainder(rawText, command)
		if err := e.Store.SetCommandAlias(actor, key, alias); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s command changed: %s", key, alias), nil
	case "commands":
		aliases := e.Store.CommandAliases()
		return fmt.Sprintf("kick: %s\nkickall: %s", aliases["kick"], aliases["kickall"]), nil
	case "bot health", "health":
		if e.Store.Role(group, actor) < RoleAdmin {
			return "", fmt.Errorf("bot health requires Admin permission")
		}
		return "", e.sendHealthMentions(ctx, client, group)
	case "bots", "status":
		if e.Store.Role(group, actor) < RoleGAdmin {
			return "", fmt.Errorf("%s requires GAdmin permission", command)
		}
		return "", e.sendBotStatus(ctx, client, group, command == "status")
	case "lkick":
		if e.Store.Role(group, actor) < RoleGAdmin {
			return "", fmt.Errorf("lkick requires GAdmin permission")
		}
		return "", e.sendAuditMentions(ctx, client, group, "kick")
	case "ljoin":
		if e.Store.Role(group, actor) < RoleGAdmin {
			return "", fmt.Errorf("ljoin requires GAdmin permission")
		}
		return "", e.sendAuditMentions(ctx, client, group, "join")
	case "protect status":
		p := e.Store.Protection(group)
		return fmt.Sprintf("Protection status:\ninvite=%t cancel=%t kick=%t qr=%t all=%t flood=%t", p.Invite, p.Cancel, p.Kick, p.QR, p.All, p.Flood), nil
	case "settings backup":
		path, err := e.Store.Backup(actor)
		if err != nil {
			return "", err
		}
		return "Settings backup created: " + path, nil
	case "settings restore":
		path, err := e.Store.Restore(actor)
		if err != nil {
			return "", err
		}
		return "Settings restored: " + path, nil
	case "all", "etiket", "@all":
		if e.Store.Role(group, actor) < RoleGAdmin {
			return "", fmt.Errorf("all requires GAdmin permission")
		}
		return "", e.mentionAll(ctx, client, group)
	case "history":
		if e.Store.Role(group, actor) < RoleGAdmin {
			return "", fmt.Errorf("history requires GAdmin permission")
		}
		return e.formatHistory(ctx, client, group)
	case "samejoin":
		if err := requireTarget(); err != nil {
			return "", err
		}
		if e.Store.Role(group, actor) < RoleGAdmin {
			return "", fmt.Errorf("samejoin requires GAdmin permission")
		}
		return e.sameJoin(ctx, client, group, target)
	case "invite":
		if err := requireTarget(); err != nil {
			return "", err
		}
		role := e.Store.Role(group, actor)
		if role < RoleGAdmin || (role == RoleGAdmin && e.Store.IsBot(target)) {
			return "", fmt.Errorf("you cannot invite this user")
		}
		return "User invited: " + target, e.invite(ctx, client, group, target)
	case "access", "roles":
		state := e.Store.Snapshot()
		room := state.Groups[group]
		gadmins := []string{}
		standbyCount := 0
		reserveMIDs := []string{}
		protection := e.Store.Protection(group)
		if room != nil {
			gadmins = room.GAdmins
			standbyCount = room.StandbyCount
			reserveMIDs = room.ReserveMIDs
		}
		return fmt.Sprintf("Creators: %s\nOwners: %s\nAdmins: %s\nGAdmins: %s\nBlacklist: %d\nGhost: %d (%s)\nProtect invite=%t cancel=%t kick=%t qr=%t all=%t flood=%t",
			strings.Join(state.Creators, ", "), strings.Join(state.Owners, ", "), strings.Join(state.Admins, ", "), strings.Join(gadmins, ", "), len(state.Blacklist), standbyCount, strings.Join(reserveMIDs, ", "), protection.Invite, protection.Cancel, protection.Kick, protection.QR, protection.All, protection.Flood), nil
	case "guard help", "help":
		return helpMenu(e.Store.Role(group, actor)), nil
	default:
		return "", nil
	}
}

func (e *Engine) addMe(ctx context.Context, reporter *lineclient.Client, group, actor string) (string, error) {
	e.mu.Lock()
	clients := make([]*lineclient.Client, 0, len(e.clients))
	for _, current := range e.clients {
		clients = append(clients, current)
	}
	e.mu.Unlock()
	sort.Slice(clients, func(i, j int) bool { return clients[i].Session.MID < clients[j].Session.MID })
	type outcome struct {
		mid   string
		added bool
		err   error
	}
	results := make(chan outcome, len(clients))
	var wait sync.WaitGroup
	for _, current := range clients {
		current := current
		wait.Add(1)
		go func() {
			defer wait.Done()
			added, err := current.EnsureFriendFromGroup(ctx, actor, group)
			results <- outcome{mid: current.Session.MID, added: added, err: err}
		}()
	}
	wait.Wait()
	close(results)
	values := make([]outcome, 0, len(clients))
	var mids []string
	for result := range results {
		values = append(values, result)
		mids = append(mids, result.mid)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].mid < values[j].mid })
	names := make(map[string]string)
	if contacts, err := reporter.GetContacts(ctx, mids); err == nil {
		for _, contact := range contacts {
			names[contact.MID] = contact.DisplayName
		}
	}
	addedCount, existingCount, failedCount := 0, 0, 0
	var output strings.Builder
	output.WriteString("Friendship result:")
	for _, result := range values {
		name := names[result.mid]
		if name == "" {
			name = result.mid
		}
		switch {
		case result.err != nil:
			failedCount++
			fmt.Fprintf(&output, "\n❌ %s — %s", name, friendlyFriendError(result.err))
		case result.added:
			addedCount++
			fmt.Fprintf(&output, "\n✅ %s — added as friend", name)
		default:
			existingCount++
			fmt.Fprintf(&output, "\nℹ️ %s — already a friend", name)
		}
	}
	fmt.Fprintf(&output, "\nTotal: %d added, %d already friends, %d failed", addedCount, existingCount, failedCount)
	return output.String(), nil
}

func friendlyFriendError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "abuse_block") || strings.Contains(text, "rate") || strings.Contains(text, "429"):
		return "LINE applied a temporary action limit; try again later"
	case strings.Contains(text, "suspended"):
		return "this account's friend-add permission is suspended"
	case strings.Contains(text, "deadline") || strings.Contains(text, "timeout"):
		return "LINE did not respond in time"
	case strings.Contains(text, "410"):
		return "LINE session is refreshing; try again"
	case strings.Contains(text, "{1:5}") || strings.Contains(text, "1:5"):
		return "LINE could not find the user from this add source (NOT_FOUND)"
	case strings.Contains(text, "{1:7}") || strings.Contains(text, "1:7"):
		return "Friend could not be added"
	case strings.Contains(text, "not found"):
		return "user not found"
	default:
		message := err.Error()
		if len(message) > 140 {
			message = message[:140] + "…"
		}
		return "LINE rejected the action: " + message
	}
}

func (e *Engine) formatHistory(ctx context.Context, client *lineclient.Client, group string) (string, error) {
	e.mu.Lock()
	items := append([]auditEvent(nil), e.audit[group]...)
	e.mu.Unlock()
	if len(items) == 0 {
		return "No group events in this runtime.", nil
	}
	if len(items) > 20 {
		items = items[len(items)-20:]
	}
	var mids []string
	for _, item := range items {
		mids = appendUnique(mids, item.Actor)
		for _, target := range item.Targets {
			mids = appendUnique(mids, target)
		}
	}
	contacts, err := client.GetContacts(ctx, mids)
	if err != nil {
		return "", err
	}
	names := make(map[string]string, len(contacts))
	for _, contact := range contacts {
		names[contact.MID] = contact.DisplayName
	}
	name := func(mid string) string {
		if value := names[mid]; value != "" {
			return value
		}
		return mid
	}
	var output strings.Builder
	output.WriteString("Recent group events:")
	for _, item := range items {
		timestamp := time.UnixMilli(item.At).Format("15:04:05")
		targetNames := make([]string, 0, len(item.Targets))
		for _, target := range item.Targets {
			targetNames = append(targetNames, name(target))
		}
		fmt.Fprintf(&output, "\n%s %s: %s → %s", timestamp, item.Action, name(item.Actor), strings.Join(targetNames, ", "))
	}
	return output.String(), nil
}

func (e *Engine) sameJoin(ctx context.Context, client *lineclient.Client, group, target string) (string, error) {
	chats, err := client.GetChats(ctx, []string{group})
	if err != nil || len(chats) != 1 {
		return "", fmt.Errorf("group join information could not be retrieved: %w", err)
	}
	joined := chats[0].JoinedAt[target]
	if joined == 0 {
		return "Target join time was not found.", nil
	}
	bucket := joined / 1000
	var matches []string
	for mid, value := range chats[0].JoinedAt {
		if mid != target && value != 0 && value/1000 == bucket {
			matches = append(matches, mid)
		}
	}
	if len(matches) == 0 {
		return "No other accounts joined in the same second.", nil
	}
	contacts, err := client.GetContacts(ctx, append([]string{target}, matches...))
	if err != nil {
		return "", err
	}
	var names []string
	for _, contact := range contacts {
		if contact.MID != target {
			names = append(names, contact.DisplayName)
		}
	}
	return fmt.Sprintf("Accounts that joined in the same second (%d):\n%s", len(names), strings.Join(names, "\n")), nil
}

func (e *Engine) kickAll(ctx context.Context, leader *lineclient.Client, group, actor string) (string, error) {
	if e.Store.Role(group, actor) < RoleAdmin {
		return "", fmt.Errorf("kickall requires Admin permission")
	}
	chats, err := leader.GetChats(ctx, []string{group})
	if err != nil || len(chats) != 1 {
		return "", fmt.Errorf("group members could not be retrieved: %w", err)
	}
	members := append([]string(nil), chats[0].Members...)
	clients := make(map[string]*lineclient.Client)
	e.mu.Lock()
	for mid, current := range e.clients {
		if current != nil && contains(members, mid) {
			clients[mid] = current
		}
	}
	e.mu.Unlock()
	workers := make([]*lineclient.Client, 0, len(clients))
	for _, current := range clients {
		workers = append(workers, current)
	}
	if len(workers) == 0 {
		workers = append(workers, leader)
	}
	targets := make([]string, 0, len(members))
	for _, mid := range members {
		if mid != "" && !e.Store.IsBot(mid) && e.Store.Role(group, mid) == RoleUser {
			targets = append(targets, mid)
		}
	}
	if len(targets) == 0 {
		return "No kickall targets; bots and privileged users are protected.", nil
	}
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	workers = e.health.rank(workers)
	const batchSize = 14
	removed, failed, offset, round := 0, 0, 0, 0
	for offset < len(targets) {
		type job struct {
			client  *lineclient.Client
			targets []string
		}
		jobs := make([]job, 0, len(workers))
		for index := 0; index < len(workers) && offset < len(targets); index++ {
			end := min(offset+batchSize, len(targets))
			worker := workers[(index+round)%len(workers)]
			jobs = append(jobs, job{client: worker, targets: append([]string(nil), targets[offset:end]...)})
			offset = end
		}
		var wait sync.WaitGroup
		var resultMu sync.Mutex
		for _, current := range jobs {
			current := current
			wait.Add(1)
			go func() {
				defer wait.Done()
				if err := e.kick(ctx, current.client, group, current.targets...); err != nil {
					e.Logger.Printf("guard kickall batch failed group=%s bot=%s targets=%d: %v", group, current.client.Session.MID, len(current.targets), err)
					resultMu.Lock()
					failed += len(current.targets)
					resultMu.Unlock()
					return
				}
				resultMu.Lock()
				removed += len(current.targets)
				resultMu.Unlock()
			}()
		}
		wait.Wait()
		round++
	}
	e.Logger.Printf("guard kickall completed group=%s actor=%s removed=%d failed=%d bots=%d rounds=%d", group, actor, removed, failed, len(workers), round)
	return fmt.Sprintf("Kickall completed: %d removed, %d failed; bots and privileged users were protected.", removed, failed), nil
}

func commandRemainder(text, command string) string {
	normalized := strings.TrimSpace(strings.ToLower(strings.TrimSpace(text)))
	return strings.TrimSpace(strings.TrimPrefix(normalized, command))
}

func (e *Engine) kick(ctx context.Context, client *lineclient.Client, group string, targets ...string) error {
	member, err := e.confirmGroupMembership(ctx, client, group)
	if err != nil {
		return err
	}
	if !member {
		return fmt.Errorf("action skipped: bot is not in the group mid=%s", client.Session.MID)
	}
	err = client.KickFromChat(ctx, group, targets...)
	e.health.record(client.Session.MID, "kick", err)
	e.recordWarAction(group, "kick", err)
	return err
}

func (e *Engine) invite(ctx context.Context, client *lineclient.Client, group string, targets ...string) error {
	member, err := e.confirmGroupMembership(ctx, client, group)
	if err != nil {
		return err
	}
	if !member {
		return fmt.Errorf("action skipped: bot is not in the group mid=%s", client.Session.MID)
	}
	err = client.InviteIntoChat(ctx, group, targets...)
	e.health.record(client.Session.MID, "invite", err)
	e.recordWarAction(group, "invite", err)
	return err
}

func (e *Engine) cancel(ctx context.Context, client *lineclient.Client, group string, targets ...string) error {
	member, err := e.confirmGroupMembership(ctx, client, group)
	if err != nil {
		return err
	}
	if !member {
		return fmt.Errorf("action skipped: bot is not in the group mid=%s", client.Session.MID)
	}
	err = client.CancelChatInvitation(ctx, group, targets...)
	e.health.record(client.Session.MID, "cancel", err)
	e.recordWarAction(group, "cancel", err)
	return err
}

func (e *Engine) confirmGroupMembership(ctx context.Context, client *lineclient.Client, group string) (bool, error) {
	chats, err := client.GetChats(ctx, []string{group})
	if err != nil {
		return false, fmt.Errorf("group membership could not be verified: %w", err)
	}
	present := false
	if len(chats) == 1 {
		present = contains(chats[0].Members, client.Session.MID)
	}
	e.setMember(group, client.Session.MID, present)
	return present, nil
}

func (e *Engine) handleMessageProtection(ctx context.Context, client *lineclient.Client, message *lineclient.Message, text string) (bool, error) {
	protection := e.Store.Protection(message.To)
	if protection.All && nativeAllMention(message.Metadata) {
		return true, e.warnOrRemove(ctx, client, message.To, message.From, "all:"+message.To+":"+message.From, "Unauthorized @All usage was blocked.")
	}
	if !protection.Flood {
		return false, nil
	}
	now := time.Now()
	key := "flood:" + message.To + ":" + message.From
	e.mu.Lock()
	state := e.spam[key]
	if state == nil {
		state = &spamState{}
		e.spam[key] = state
	}
	cutoff := now.Add(-5 * time.Second)
	kept := state.Events[:0]
	for _, event := range state.Events {
		if event.After(cutoff) {
			kept = append(kept, event)
		}
	}
	state.Events = append(kept, now)
	flooded := len(state.Events) >= 8
	if flooded {
		state.Events = nil
	}
	e.mu.Unlock()
	if !flooded {
		return false, nil
	}
	return true, e.warnOrRemove(ctx, client, message.To, message.From, key+":penalty", "Flood protection: slow down messages, stickers, and mentions.")
}

func nativeAllMention(metadata map[any]any) bool {
	for key, value := range metadata {
		if strings.EqualFold(fmt.Sprint(key), "MENTION") {
			var document struct {
				Mentionees []map[string]any `json:"MENTIONEES"`
			}
			if raw, ok := value.(string); ok && json.Unmarshal([]byte(raw), &document) == nil {
				for _, mention := range document.Mentionees {
					if fmt.Sprint(mention["A"]) == "1" {
						return true
					}
				}
			}
		}
	}
	return false
}

func (e *Engine) warnOrRemove(ctx context.Context, client *lineclient.Client, group, actor, key, warning string) error {
	now := time.Now()
	e.mu.Lock()
	state := e.spam[key]
	if state == nil {
		state = &spamState{}
		e.spam[key] = state
	}
	repeat := !state.Warned.IsZero() && now.Sub(state.Warned) < 60*time.Second
	state.Warned = now
	e.mu.Unlock()
	if !repeat {
		return e.reply(ctx, client, group, warning)
	}
	return e.kick(ctx, client, group, actor)
}

func (e *Engine) sendMIDMentions(ctx context.Context, client *lineclient.Client, group, heading string, mids []string, suffixes []string) error {
	contacts, err := client.GetContacts(ctx, mids)
	if err != nil {
		return err
	}
	namesByMID := make(map[string]string, len(contacts))
	for _, contact := range contacts {
		namesByMID[contact.MID] = contact.DisplayName
	}
	names := make([]string, 0, len(mids))
	selected := make([]string, 0, len(mids))
	selectedSuffixes := make([]string, 0, len(mids))
	for index, mid := range mids {
		name := namesByMID[mid]
		if name == "" {
			name = mid
		}
		names, selected = append(names, name), append(selected, mid)
		if index < len(suffixes) {
			selectedSuffixes = append(selectedSuffixes, suffixes[index])
		} else {
			selectedSuffixes = append(selectedSuffixes, "")
		}
	}
	toType := int32(2)
	_, err = client.SendMentions(ctx, group, heading, names, selected, selectedSuffixes, &toType)
	return err
}

func (e *Engine) sendBotStatus(ctx context.Context, client *lineclient.Client, group string, detailed bool) error {
	values := e.health.snapshots()
	mids, suffixes := make([]string, 0, len(values)), make([]string, 0, len(values))
	members, invitees := map[string]bool{}, map[string]bool{}
	if detailed {
		if chats, err := client.GetChats(ctx, []string{group}); err == nil && len(chats) == 1 {
			for _, mid := range chats[0].Members {
				members[mid] = true
			}
			for _, mid := range chats[0].Invitees {
				invitees[mid] = true
			}
		}
	}
	e.mu.Lock()
	for _, value := range values {
		current := e.clients[value.MID]
		location := "outside"
		if members[value.MID] || (!detailed && e.members[group][value.MID]) {
			location = "in-group"
		} else if invitees[value.MID] {
			location = "invited"
		}
		cooldown := "ready"
		if remaining := time.Until(value.CooldownEnd).Round(time.Second); remaining > 0 {
			cooldown = remaining.String()
		}
		detail := fmt.Sprintf("active • %s • cooldown=%s", location, cooldown)
		if detailed && current != nil {
			detail += fmt.Sprintf(" • E2EE=%t • revision=%d", len(current.Session.DeviceKeys) > 0, current.Session.SyncState.Revision)
		}
		mids, suffixes = append(mids, value.MID), append(suffixes, detail)
	}
	e.mu.Unlock()
	heading := "Bots:"
	if detailed {
		heading = "Bot status:"
	}
	return e.sendMIDMentions(ctx, client, group, heading, mids, suffixes)
}

func (e *Engine) sendAuditMentions(ctx context.Context, client *lineclient.Client, group, action string) error {
	e.mu.Lock()
	items := append([]auditEvent(nil), e.audit[group]...)
	e.mu.Unlock()
	actorNames := map[string]string{}
	if action == "kick" {
		var actors []string
		for _, item := range items {
			if item.Action == action {
				actors = appendUnique(actors, item.Actor)
			}
		}
		if contacts, err := client.GetContacts(ctx, actors); err == nil {
			for _, contact := range contacts {
				actorNames[contact.MID] = contact.DisplayName
			}
		}
	}
	var mids, suffixes []string
	for index := len(items) - 1; index >= 0 && len(mids) < 15; index-- {
		item := items[index]
		if item.Action != action {
			continue
		}
		if action == "kick" {
			for _, target := range item.Targets {
				mids = append(mids, target)
				actor := actorNames[item.Actor]
				if actor == "" {
					actor = item.Actor
				}
				suffixes = append(suffixes, fmt.Sprintf("kicked-by=%s • %s", actor, time.UnixMilli(item.At).Format("15:04:05")))
			}
		} else {
			mids = append(mids, item.Actor)
			same := 0
			for _, other := range items {
				if other.Action == "join" && other.At/1000 == item.At/1000 {
					same++
				}
			}
			suffix := time.UnixMilli(item.At).Format("15:04:05")
			if same > 1 {
				suffix += fmt.Sprintf(" • same-second=%d", same)
			}
			suffixes = append(suffixes, suffix)
		}
	}
	if len(mids) == 0 {
		return e.reply(ctx, client, group, "No records in this runtime.")
	}
	heading := "Recent removals:"
	if action == "join" {
		heading = "Recent joins:"
	}
	return e.sendMIDMentions(ctx, client, group, heading, mids, suffixes)
}

func (e *Engine) formatReaders(ctx context.Context, client *lineclient.Client, enabled bool, readers []string) (string, error) {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	if len(readers) == 0 {
		return fmt.Sprintf("Reader tracking: %s\nNo readers yet.", status), nil
	}
	contacts, err := client.GetContacts(ctx, readers)
	if err != nil {
		return "", fmt.Errorf("reader names could not be retrieved: %w", err)
	}
	names := make(map[string]string, len(contacts))
	for _, contact := range contacts {
		if contact.MID != "" && contact.DisplayName != "" {
			names[contact.MID] = contact.DisplayName
		}
	}
	var result strings.Builder
	fmt.Fprintf(&result, "Reader tracking: %s\nReaders (%d):", status, len(readers))
	for index, mid := range readers {
		name := names[mid]
		if name == "" {
			name = "Unknown user"
		}
		fmt.Fprintf(&result, "\n%d. %s", index+1, name)
	}
	return result.String(), nil
}

func (e *Engine) sendReaderMentions(ctx context.Context, client *lineclient.Client, group string, readers []string, heading string) error {
	contacts, err := client.GetContacts(ctx, readers)
	if err != nil {
		return err
	}
	namesByMID := make(map[string]string, len(contacts))
	for _, contact := range contacts {
		namesByMID[contact.MID] = contact.DisplayName
	}
	var names, mids []string
	for _, mid := range readers {
		if name := namesByMID[mid]; name != "" {
			names, mids = append(names, name), append(mids, mid)
		}
	}
	if len(mids) == 0 {
		return fmt.Errorf("reader contact information could not be retrieved")
	}
	toType := int32(2)
	_, err = client.SendMentions(ctx, group, heading, names, mids, nil, &toType)
	return err
}

func (e *Engine) sendHealthMentions(ctx context.Context, client *lineclient.Client, group string) error {
	values := e.health.snapshots()
	mids := make([]string, 0, len(values))
	for _, value := range values {
		mids = append(mids, value.MID)
	}
	contacts, err := client.GetContacts(ctx, mids)
	if err != nil {
		return err
	}
	namesByMID := make(map[string]string, len(contacts))
	for _, contact := range contacts {
		namesByMID[contact.MID] = contact.DisplayName
	}
	names, suffixes := make([]string, 0, len(values)), make([]string, 0, len(values))
	selected := make([]string, 0, len(values))
	for _, value := range values {
		name := namesByMID[value.MID]
		if name == "" {
			name = value.MID
		}
		cooldown := "ready"
		if remaining := time.Until(value.CooldownEnd).Round(time.Second); remaining > 0 {
			cooldown = remaining.String()
		}
		names = append(names, name)
		selected = append(selected, value.MID)
		suffixes = append(suffixes, fmt.Sprintf("kick=%d invite=%d cancel=%d ok=%d err=%d cooldown=%s", value.Kick, value.Invite, value.Cancel, value.Success, value.Failures, cooldown))
	}
	toType := int32(2)
	_, err = client.SendMentions(ctx, group, "Bot health:", names, selected, suffixes, &toType)
	return err
}

func (e *Engine) mentionAll(ctx context.Context, client *lineclient.Client, group string) error {
	toType := int32(2)
	_, err := client.SendAllMention(ctx, group, &toType)
	return err
}

func (e *Engine) leaveBotFleet(ctx context.Context, group string, leader *lineclient.Client) error {
	chats, err := leader.GetChats(ctx, []string{group})
	if err != nil {
		return err
	}
	if len(chats) != 1 {
		return fmt.Errorf("group members could not be retrieved")
	}
	e.mu.Lock()
	clients := make(map[string]*lineclient.Client, len(e.clients))
	for mid, current := range e.clients {
		clients[mid] = current
	}
	e.mu.Unlock()
	var failures []string
	left := 0
	for _, member := range chats[0].Members {
		current := clients[member]
		if current == nil {
			continue
		}
		if err := current.LeaveChat(ctx, group); err != nil {
			failures = append(failures, member)
			e.Logger.Printf("guard fleet leave failed group=%s bot=%s: %v", group, member, err)
			continue
		}
		e.setMember(group, member, false)
		left++
	}
	e.Logger.Printf("guard fleet left group=%s count=%d failed=%d", group, left, len(failures))
	if len(failures) > 0 {
		return fmt.Errorf("%d bots could not leave", len(failures))
	}
	return nil
}

func (e *Engine) reply(ctx context.Context, client *lineclient.Client, group, text string) error {
	toType := int32(2)
	_, err := client.SendMessage(ctx, group, text, &toType)
	return err
}

func (e *Engine) userTicketLinks(ctx context.Context) (string, error) {
	e.mu.Lock()
	clients := make([]*lineclient.Client, 0, len(e.clients))
	for mid, current := range e.clients {
		if current != nil && e.kinds[mid] == "primary" {
			clients = append(clients, current)
		}
	}
	e.mu.Unlock()
	sort.Slice(clients, func(i, j int) bool { return clients[i].Session.MID < clients[j].Session.MID })
	if len(clients) == 0 {
		return "", fmt.Errorf("no active primary bot")
	}
	lines := []string{"Bot friend-add links:"}
	for index, current := range clients {
		if index > 0 {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			}
		}
		profile, err := current.GetProfile(ctx)
		if err != nil {
			lines = append(lines, fmt.Sprintf("❌ %s — profile could not be retrieved", current.Session.MID))
			continue
		}
		ticket, err := current.GenerateUserTicket(ctx, 0, 1)
		if err != nil {
			lines = append(lines, fmt.Sprintf("❌ %s — ticket could not be generated", profile.DisplayName))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s\n%s", profile.DisplayName, ticket.URL()))
	}
	return strings.Join(lines, "\n"), nil
}

func (e *Engine) duplicate(key string) bool {
	if key == "" {
		return false
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for current, expires := range e.seen {
		if now.After(expires) {
			delete(e.seen, current)
		}
	}
	if expires, exists := e.seen[key]; exists && now.Before(expires) {
		return true
	}
	e.seen[key] = now.Add(10 * time.Second)
	return false
}

func parseCommand(text string, metadata map[any]any) (string, []string) {
	normalized := strings.TrimSpace(strings.ToLower(strings.TrimSpace(text)))
	if strings.HasPrefix(normalized, ".") {
		return "", nil
	}
	known := []string{
		"war sensitivity", "war whitelist add", "war whitelist del", "war quarantine", "war cooldown",
		"war dryrun on", "war dryrun off", "war auto on", "war auto off", "war dashboard", "war suspects",
		"war whitelist", "war report", "war status", "war level", "war lock", "war unlock", "war pardon",
		"war clear", "war on", "war off", "leader",
		"invite protect on", "invite protect off", "cancel protect on", "cancel protect off", "kick protect on", "kick protect off",
		"qr protect on", "qr protect off", "all protect on", "all protect off", "flood protect on", "flood protect off",
		"protect status", "protect on", "protect off", "settings backup", "settings restore", "setcmd kickall", "setcmd kick",
		"lurk mention", "lurk names", "lurk on", "lurk off", "add creator", "del creator", "add owner", "del owner",
		"add admin", "del admin", "add gadmin", "del gadmin", "clear blacklist", "clearban", "blacklist", "unban", "kickall", "kick", "invite",
		"guard help", "bot health", "samejoin", "history", "health", "status", "bots", "lkick", "ljoin", "access",
		"roles", "commands", "help", "ping", "speed", "sp", "ticket", "readers", "lurk", "ghost 1", "ghost 2", "ghost off",
		"add me", "@all", "etiket", "all", "bye",
	}
	command := ""
	for _, candidate := range known {
		if normalized == candidate || strings.HasPrefix(normalized, candidate+" ") {
			command = candidate
			break
		}
	}
	if command == "" {
		return "", nil
	}
	targets := mentionMIDs(metadata)
	rest := strings.TrimSpace(strings.TrimPrefix(normalized, command))
	for _, value := range strings.Fields(rest) {
		if len(value) == 33 && (value[0] == 'u' || value[0] == 'U') && !contains(targets, value) {
			targets = append(targets, value)
		}
	}
	return command, targets
}

func parseConfiguredCommand(text string, metadata map[any]any, aliases map[string]string) (string, []string) {
	normalized := strings.TrimSpace(strings.ToLower(strings.TrimSpace(text)))
	if strings.HasPrefix(normalized, ".") {
		return "", nil
	}
	for _, canonical := range []string{"kickall", "kick"} {
		alias := strings.TrimSpace(strings.ToLower(aliases[canonical]))
		if alias == "" || alias == canonical {
			continue
		}
		if normalized == alias || (canonical == "kick" && strings.HasPrefix(normalized, alias+" ")) {
			rewritten := canonical + strings.TrimPrefix(normalized, alias)
			return parseCommand(rewritten, metadata)
		}
	}
	return parseCommand(text, metadata)
}

func mentionMIDs(metadata map[any]any) []string {
	var raw string
	for key, value := range metadata {
		if strings.EqualFold(fmt.Sprint(key), "MENTION") {
			raw, _ = value.(string)
			break
		}
	}
	if raw == "" {
		return nil
	}
	var document struct {
		Mentionees []struct {
			MID string `json:"M"`
		} `json:"MENTIONEES"`
	}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil
	}
	result := make([]string, 0, len(document.Mentionees))
	for _, mention := range document.Mentionees {
		if mention.MID != "" && !contains(result, mention.MID) {
			result = append(result, mention.MID)
		}
	}
	return result
}

func eventKey(operation lineclient.Operation) string {
	return fmt.Sprintf("event:%d:%s:%s:%s", operation.Type, operation.Param1, operation.Param2, operation.Param3)
}

func splitMIDs(value string) []string {
	var result []string
	for _, mid := range strings.Split(value, "\x1e") {
		if mid = strings.TrimSpace(mid); mid != "" && !contains(result, mid) {
			result = append(result, mid)
		}
	}
	return result
}
