package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

type Role int

const (
	RoleUser Role = iota
	RoleGAdmin
	RoleAdmin
	RoleOwner
	RoleCreator
)

func (r Role) String() string {
	switch r {
	case RoleCreator:
		return "creator"
	case RoleOwner:
		return "owner"
	case RoleAdmin:
		return "admin"
	case RoleGAdmin:
		return "gadmin"
	default:
		return "user"
	}
}

type GroupState struct {
	GAdmins      []string         `json:"gadmins,omitempty"`
	StandbyCount int              `json:"standby_count,omitempty"`
	ReserveMIDs  []string         `json:"reserve_mids,omitempty"`
	Protection   *ProtectionState `json:"protection,omitempty"`
	Lurk         bool             `json:"lurk,omitempty"`
	Readers      []string         `json:"-"`
	War          *WarState        `json:"war,omitempty"`
}

type WarState struct {
	Enabled     bool     `json:"enabled"`
	Level       int      `json:"level"`
	Until       int64    `json:"until,omitempty"`
	Auto        bool     `json:"auto,omitempty"`
	Sensitivity string   `json:"sensitivity,omitempty"`
	CooldownSec int64    `json:"cooldown_sec,omitempty"`
	Locked      bool     `json:"locked,omitempty"`
	DryRun      bool     `json:"dry_run,omitempty"`
	Whitelist   []string `json:"whitelist,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	StartedBy   string   `json:"started_by,omitempty"`
}

func (s *Store) SetLurk(group, actor string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked(group, actor) < RoleGAdmin {
		return fmt.Errorf("lurk settings require GAdmin permission")
	}
	room := ensureGroup(&s.state, group)
	room.Lurk = enabled
	room.Readers = nil
	return s.saveLocked()
}

func (s *Store) RecordReader(group, mid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	room := s.state.Groups[group]
	if room == nil || !room.Lurk || mid == "" || contains(room.Readers, mid) {
		return false
	}
	room.Readers = append(room.Readers, mid)
	return true
}

func (s *Store) LurkState(group string) (bool, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	room := s.state.Groups[group]
	if room == nil {
		return false, nil
	}
	return room.Lurk, append([]string(nil), room.Readers...)
}

type ProtectionState struct{ Invite, Cancel, Kick, QR, All, Flood bool }

func (s *Store) Protection(group string) ProtectionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if room := s.state.Groups[group]; room != nil && room.Protection != nil {
		return *room.Protection
	}
	return ProtectionState{}
}

func (s *Store) SetProtection(group, actor, scope string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked(group, actor) < RoleAdmin {
		return fmt.Errorf("protection settings require Admin permission")
	}
	room := ensureGroup(&s.state, group)
	if room.Protection == nil {
		value := ProtectionState{}
		room.Protection = &value
	}
	switch scope {
	case "all":
		room.Protection.Invite = enabled
		room.Protection.Cancel = enabled
		room.Protection.Kick = enabled
		room.Protection.QR = enabled
	case "invite":
		room.Protection.Invite = enabled
	case "cancel":
		room.Protection.Cancel = enabled
	case "kick":
		room.Protection.Kick = enabled
	case "qr":
		room.Protection.QR = enabled
	case "mention":
		room.Protection.All = enabled
	case "flood":
		room.Protection.Flood = enabled
	default:
		return fmt.Errorf("unknown protection scope")
	}
	return s.saveLocked()
}

func (s *Store) Backup(actor string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.roleLocked("", actor) != RoleCreator {
		return "", fmt.Errorf("settings backup requires Creator permission")
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return "", err
	}
	path := s.path + ".backup"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) Restore(actor string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked("", actor) != RoleCreator {
		return "", fmt.Errorf("settings restore requires Creator permission")
	}
	path := s.path + ".backup"
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("settings backup could not be read: %w", err)
	}
	data, _, err = migrateCreatorFormat(data)
	if err != nil {
		return "", err
	}
	var restored State
	if err := json.Unmarshal(data, &restored); err != nil {
		return "", fmt.Errorf("settings backup is invalid: %w", err)
	}
	if !contains(restored.Creators, actor) {
		return "", fmt.Errorf("backup does not contain the current Creator")
	}
	s.state = restored
	s.normalizeLocked()
	return path, s.saveLocked()
}

func (s *Store) SetReservePlan(group, actor string, count int, mids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked(group, actor) < RoleAdmin {
		return fmt.Errorf("ghost settings require Admin permission")
	}
	if count < 0 || count > 2 || len(mids) < count {
		return fmt.Errorf("ghost count must be 0, 1, or 2 and enough reserve accounts must be available")
	}
	room := ensureGroup(&s.state, group)
	room.StandbyCount = count
	room.ReserveMIDs = append([]string(nil), mids[:count]...)
	return s.saveLocked()
}

func (s *Store) ReservePlan(group string) (int, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	room := s.state.Groups[group]
	if room == nil {
		return 0, nil
	}
	return room.StandbyCount, append([]string(nil), room.ReserveMIDs...)
}

type State struct {
	Version   int                    `json:"version"`
	Creators  []string               `json:"creator,omitempty"`
	Owners    []string               `json:"owners,omitempty"`
	Admins    []string               `json:"admins,omitempty"`
	Blacklist []string               `json:"blacklist,omitempty"`
	Bots      []string               `json:"bots,omitempty"`
	Commands  map[string]string      `json:"commands,omitempty"`
	Groups    map[string]*GroupState `json:"groups,omitempty"`
}

type Store struct {
	path  string
	mu    sync.RWMutex
	state State
}

func OpenStore(path string) (*Store, error) {
	store := &Store{path: path, state: State{Version: 1, Groups: make(map[string]*GroupState)}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("guard state could not be read: %w", err)
	}
	data, migrated, err := migrateCreatorFormat(data)
	if err != nil {
		return nil, fmt.Errorf("guard state is invalid: %w", err)
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("guard state is invalid: %w", err)
	}
	store.normalizeLocked()
	if migrated {
		if err := store.saveLocked(); err != nil {
			return nil, fmt.Errorf("legacy guard state could not be migrated: %w", err)
		}
	}
	return store, nil
}

func migrateCreatorFormat(data []byte) ([]byte, bool, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, false, err
	}
	raw, exists := document["creator"]
	if !exists || len(raw) == 0 || raw[0] == '[' {
		return data, false, nil
	}
	var creator string
	if err := json.Unmarshal(raw, &creator); err != nil {
		return nil, false, fmt.Errorf("creator field could not be read: %w", err)
	}
	creators := []string{}
	if creator != "" {
		creators = append(creators, creator)
	}
	encoded, err := json.Marshal(creators)
	if err != nil {
		return nil, false, err
	}
	document["creator"] = encoded
	converted, err := json.Marshal(document)
	if err != nil {
		return nil, false, err
	}
	return converted, true, nil
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) Creator() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.state.Creators) == 0 {
		return ""
	}
	return s.state.Creators[0]
}

func (s *Store) BootstrapCreator(inviter string) (bool, error) {
	if inviter == "" {
		return false, fmt.Errorf("inviter MID is required to set Creator")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Creators) != 0 {
		return false, nil
	}
	s.state.Creators = []string{inviter}
	s.normalizeLocked()
	return true, s.saveLocked()
}

func (s *Store) RegisterBot(mid string) error {
	if mid == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if contains(s.state.Bots, mid) {
		return nil
	}
	s.state.Bots = append(s.state.Bots, mid)
	s.normalizeLocked()
	return s.saveLocked()
}

func (s *Store) IsBot(mid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return contains(s.state.Bots, mid)
}

func (s *Store) IsBlacklisted(mid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return contains(s.state.Blacklist, mid)
}

func (s *Store) CommandAliases() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := map[string]string{"kick": "kick", "kickall": "kickall"}
	for key, value := range s.state.Commands {
		if value != "" {
			result[key] = value
		}
	}
	return result
}

func (s *Store) SetCommandAlias(actor, command, alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked("", actor) < RoleAdmin {
		return fmt.Errorf("changing commands requires Admin permission")
	}
	if command != "kick" && command != "kickall" {
		return fmt.Errorf("only kick and kickall can be changed")
	}
	alias = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(alias, ".")))
	if alias == "" || strings.ContainsAny(alias, "\r\n") {
		return fmt.Errorf("a valid command name is required")
	}
	if s.state.Commands == nil {
		s.state.Commands = make(map[string]string)
	}
	s.state.Commands[command] = alias
	return s.saveLocked()
}

func (s *Store) Role(group, mid string) Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.roleLocked(group, mid)
}

func (s *Store) CanInvite(group, actor string) bool {
	return s.Role(group, actor) >= RoleGAdmin
}

func (s *Store) CanKick(group, actor, target string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	actorRole := s.roleLocked(group, actor)
	targetRole := s.roleLocked(group, target)
	if actorRole < RoleGAdmin || actor == target {
		return false
	}
	if contains(s.state.Bots, target) {
		return actorRole == RoleCreator
	}
	return actorRole > targetRole
}

func (s *Store) AddOwner(actor, target string) error {
	return s.mutateRole("add owner", actor, target, "", RoleCreator, func(state *State) {
		state.Owners = appendUnique(state.Owners, target)
	})
}

func (s *Store) AddCreator(actor, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked("", actor) != RoleCreator {
		return fmt.Errorf("add creator requires Creator permission")
	}
	if target == "" || contains(s.state.Bots, target) {
		return fmt.Errorf("this user cannot be made Creator")
	}
	s.state.Creators = appendUnique(s.state.Creators, target)
	s.normalizeLocked()
	return s.saveLocked()
}

func (s *Store) DelCreator(actor, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked("", actor) != RoleCreator {
		return fmt.Errorf("del creator requires Creator permission")
	}
	if actor == target || !contains(s.state.Creators, target) || len(s.state.Creators) <= 1 {
		return fmt.Errorf("you cannot remove yourself or the last Creator")
	}
	s.state.Creators = remove(s.state.Creators, target)
	return s.saveLocked()
}

func (s *Store) DelOwner(actor, target string) error {
	return s.mutateRole("del owner", actor, target, "", RoleCreator, func(state *State) {
		state.Owners = remove(state.Owners, target)
	})
}

func (s *Store) AddAdmin(actor, target string) error {
	return s.mutateRole("add admin", actor, target, "", RoleOwner, func(state *State) {
		state.Admins = appendUnique(state.Admins, target)
	})
}

func (s *Store) DelAdmin(actor, target string) error {
	return s.mutateRole("del admin", actor, target, "", RoleOwner, func(state *State) {
		state.Admins = remove(state.Admins, target)
	})
}

func (s *Store) AddGAdmin(group, actor, target string) error {
	if group == "" {
		return fmt.Errorf("GAdmin can only be granted inside a group")
	}
	return s.mutateRole("add gadmin", actor, target, group, RoleAdmin, func(state *State) {
		room := ensureGroup(state, group)
		room.GAdmins = appendUnique(room.GAdmins, target)
	})
}

func (s *Store) DelGAdmin(group, actor, target string) error {
	if group == "" {
		return fmt.Errorf("GAdmin can only be removed inside a group")
	}
	return s.mutateRole("del gadmin", actor, target, group, RoleAdmin, func(state *State) {
		room := ensureGroup(state, group)
		room.GAdmins = remove(room.GAdmins, target)
	})
}

func (s *Store) AddBlacklist(group, actor, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	actorRole := s.roleLocked(group, actor)
	targetRole := s.roleLocked(group, target)
	if actorRole < RoleAdmin {
		return fmt.Errorf("blacklist requires Admin permission")
	}
	if target == "" || actor == target || contains(s.state.Bots, target) || targetRole >= actorRole {
		return fmt.Errorf("this user cannot be blacklisted")
	}
	s.state.Blacklist = appendUnique(s.state.Blacklist, target)
	s.normalizeLocked()
	return s.saveLocked()
}

func (s *Store) Unban(group, actor, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked(group, actor) < RoleGAdmin {
		return fmt.Errorf("unban requires GAdmin permission")
	}
	s.state.Blacklist = remove(s.state.Blacklist, target)
	return s.saveLocked()
}

func (s *Store) ClearBlacklist(group, actor string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked(group, actor) < RoleAdmin {
		return 0, fmt.Errorf("clearing the blacklist requires Admin permission")
	}
	removed := len(s.state.Blacklist)
	if removed == 0 {
		return 0, nil
	}
	s.state.Blacklist = nil
	return removed, s.saveLocked()
}

func (s *Store) AutoBlacklist(group, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if target == "" || contains(s.state.Bots, target) || s.roleLocked(group, target) != RoleUser {
		return fmt.Errorf("a protected user cannot be automatically blacklisted")
	}
	s.state.Blacklist = appendUnique(s.state.Blacklist, target)
	return s.saveLocked()
}

func (s *Store) mutateRole(action, actor, target, group string, minimum Role, change func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	actorRole := s.roleLocked(group, actor)
	targetRole := s.roleLocked(group, target)
	if actorRole < minimum {
		return fmt.Errorf("%s requires %s permission", action, minimum)
	}
	if target == "" || actor == target || contains(s.state.Bots, target) || contains(s.state.Creators, target) {
		return fmt.Errorf("%s cannot be performed on this user", action)
	}
	if targetRole >= actorRole {
		return fmt.Errorf("a user with equal or higher permission cannot be changed")
	}
	change(&s.state)
	s.normalizeLocked()
	return s.saveLocked()
}

func (s *Store) roleLocked(group, mid string) Role {
	if mid == "" {
		return RoleUser
	}
	if contains(s.state.Creators, mid) {
		return RoleCreator
	}
	if contains(s.state.Owners, mid) {
		return RoleOwner
	}
	if contains(s.state.Admins, mid) {
		return RoleAdmin
	}
	if room := s.state.Groups[group]; room != nil && contains(room.GAdmins, mid) {
		return RoleGAdmin
	}
	return RoleUser
}

func (s *Store) normalizeLocked() {
	if s.state.Version == 0 {
		s.state.Version = 1
	}
	if s.state.Groups == nil {
		s.state.Groups = make(map[string]*GroupState)
	}
	s.state.Bots = unique(s.state.Bots)
	s.state.Creators = unique(s.state.Creators)
	s.state.Owners = removeMany(unique(s.state.Owners), s.state.Creators)
	s.state.Admins = removeMany(unique(s.state.Admins), append(append([]string{}, s.state.Owners...), s.state.Creators...))
	protected := append(append(append([]string{}, s.state.Bots...), s.state.Owners...), s.state.Admins...)
	protected = append(protected, s.state.Creators...)
	s.state.Blacklist = removeMany(unique(s.state.Blacklist), protected)
	for _, room := range s.state.Groups {
		if room != nil {
			room.GAdmins = removeMany(unique(room.GAdmins), protected)
		}
	}
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".guard-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func ensureGroup(state *State, group string) *GroupState {
	if state.Groups == nil {
		state.Groups = make(map[string]*GroupState)
	}
	if state.Groups[group] == nil {
		state.Groups[group] = &GroupState{}
	}
	return state.Groups[group]
}

func cloneState(value State) State {
	data, _ := json.Marshal(value)
	var result State
	_ = json.Unmarshal(data, &result)
	return result
}

func contains(values []string, target string) bool { return slices.Contains(values, target) }

func appendUnique(values []string, target string) []string {
	if target != "" && !contains(values, target) {
		return append(values, target)
	}
	return values
}

func unique(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = appendUnique(result, value)
	}
	return result
}

func remove(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func removeMany(values, targets []string) []string {
	for _, target := range targets {
		values = remove(values, target)
	}
	return values
}
