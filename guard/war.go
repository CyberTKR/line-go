package guard

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	lineclient "github.com/CyberTKR/line-go/client"
)

type warRuntime struct {
	Started                                              time.Time
	Kicks, Invites, Cancels, QRClosed, Rescues, Failures uint64
	Suspects                                             map[string]int
	Quarantine                                           map[string]time.Time
}

func defaultWar() WarState { return WarState{Level: 2, Sensitivity: "medium", CooldownSec: 120} }

func (s *Store) War(group string) WarState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	room := s.state.Groups[group]
	if room == nil || room.War == nil {
		return defaultWar()
	}
	value := *room.War
	value.Whitelist = append([]string(nil), room.War.Whitelist...)
	if value.Level == 0 {
		value.Level = 2
	}
	if value.Sensitivity == "" {
		value.Sensitivity = "medium"
	}
	return value
}

func (s *Store) UpdateWar(group, actor string, update func(*WarState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleLocked(group, actor) < RoleOwner {
		return fmt.Errorf("war settings require Owner or Creator permission")
	}
	room := ensureGroup(&s.state, group)
	if room.War == nil {
		value := defaultWar()
		room.War = &value
	}
	if err := update(room.War); err != nil {
		return err
	}
	room.War.Whitelist = unique(room.War.Whitelist)
	return s.saveLocked()
}

func (s *Store) expireWar(group string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if room := s.state.Groups[group]; room != nil && room.War != nil && room.War.Enabled {
		room.War.Enabled, room.War.Locked = false, false
		_ = s.saveLocked()
	}
}

func (s *Store) activateWarAuto(group, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	room := ensureGroup(&s.state, group)
	if room.War == nil {
		value := defaultWar()
		room.War = &value
	}
	if !room.War.Auto || room.War.Enabled {
		return nil
	}
	room.War.Enabled, room.War.Until, room.War.Reason, room.War.StartedBy = true, time.Now().Add(5*time.Minute).UnixMilli(), reason, "auto"
	return s.saveLocked()
}

func (e *Engine) warActive(group string) (WarState, bool) {
	war := e.Store.War(group)
	if war.Enabled && war.Until > 0 && time.Now().UnixMilli() >= war.Until {
		e.Store.expireWar(group)
		war.Enabled = false
	}
	return war, war.Enabled
}

func (e *Engine) executeWar(ctx context.Context, client *lineclient.Client, group, actor, command, target string) (string, error) {
	role := e.Store.Role(group, actor)
	if role < RoleOwner {
		return "", fmt.Errorf("war commands require Owner or Creator permission")
	}
	fields := strings.Fields(command)
	switch {
	case strings.HasPrefix(command, "war on"):
		duration := 5 * time.Minute
		if len(fields) > 2 {
			parsed, err := time.ParseDuration(fields[2])
			if err != nil {
				return "", fmt.Errorf("duration examples: 5m, 30s, 1h")
			}
			duration = parsed
		}
		if duration < 30*time.Second || duration > 24*time.Hour {
			return "", fmt.Errorf("war duration must be between 30s and 24h")
		}
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error {
			w.Enabled = true
			w.Until = time.Now().Add(duration).UnixMilli()
			w.StartedBy = actor
			w.Reason = "manual"
			return nil
		})
		if err == nil {
			e.resetWarRuntime(group)
		}
		return fmt.Sprintf("War mode level %d enabled; duration=%s", e.Store.War(group).Level, duration), err
	case command == "war off":
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error { w.Enabled = false; w.Locked = false; return nil })
		return "War mode disabled.", err
	case command == "war status" || command == "war dashboard":
		return e.warStatus(group), nil
	case command == "war report":
		return e.warReport(group), nil
	case command == "war suspects":
		return "", e.sendWarSuspects(ctx, client, group)
	case strings.HasPrefix(command, "war level "):
		level := int(command[len(command)-1] - '0')
		if level < 1 || level > 3 {
			return "", fmt.Errorf("war level must be 1, 2, or 3")
		}
		if level == 3 && role != RoleCreator {
			return "", fmt.Errorf("level 3 can only be enabled by a Creator")
		}
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error { w.Level = level; return nil })
		return fmt.Sprintf("War level=%d", level), err
	case command == "war lock" || command == "war unlock":
		on := command == "war lock"
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error { w.Locked = on; return nil })
		return fmt.Sprintf("War lock=%t", on), err
	case command == "war auto on" || command == "war auto off":
		on := strings.HasSuffix(command, "on")
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error { w.Auto = on; return nil })
		return fmt.Sprintf("War auto=%t", on), err
	case strings.HasPrefix(command, "war sensitivity "):
		value := fields[len(fields)-1]
		if value != "low" && value != "medium" && value != "high" {
			return "", fmt.Errorf("sensitivity must be low, medium, or high")
		}
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error { w.Sensitivity = value; return nil })
		return "War sensitivity=" + value, err
	case strings.HasPrefix(command, "war cooldown "):
		d, err := time.ParseDuration(fields[len(fields)-1])
		if err != nil {
			return "", err
		}
		err = e.Store.UpdateWar(group, actor, func(w *WarState) error { w.CooldownSec = int64(d.Seconds()); return nil })
		return "War cooldown=" + d.String(), err
	case command == "war dryrun on" || command == "war dryrun off":
		on := strings.HasSuffix(command, "on")
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error { w.DryRun = on; return nil })
		return fmt.Sprintf("War dryrun=%t", on), err
	case command == "war whitelist":
		w := e.Store.War(group)
		if len(w.Whitelist) == 0 {
			return "War whitelist is empty.", nil
		}
		return "", e.sendMIDMentions(ctx, client, group, "War whitelist:", w.Whitelist, nil)
	case command == "war whitelist add" || command == "war whitelist del":
		if target == "" {
			return "", fmt.Errorf("user mention is required")
		}
		add := strings.HasSuffix(command, "add")
		err := e.Store.UpdateWar(group, actor, func(w *WarState) error {
			if add {
				w.Whitelist = appendUnique(w.Whitelist, target)
			} else {
				w.Whitelist = remove(w.Whitelist, target)
			}
			return nil
		})
		return fmt.Sprintf("War whitelist updated: %s", target), err
	case strings.HasPrefix(command, "war pardon"):
		if target == "" {
			return "", fmt.Errorf("user mention is required")
		}
		e.mu.Lock()
		if r := e.war[group]; r != nil {
			delete(r.Suspects, target)
			delete(r.Quarantine, target)
		}
		e.mu.Unlock()
		return "Suspect and quarantine records cleared.", nil
	case strings.HasPrefix(command, "war quarantine"):
		if target == "" {
			return "", fmt.Errorf("user mention is required")
		}
		e.mu.Lock()
		r := e.ensureWarRuntimeLocked(group)
		r.Quarantine[target] = time.Now().Add(10 * time.Minute)
		e.mu.Unlock()
		return "User quarantined for 10 minutes.", nil
	case command == "war clear":
		e.resetWarRuntime(group)
		return "Temporary war records cleared.", nil
	}
	return "", nil
}

func (e *Engine) ensureWarRuntimeLocked(group string) *warRuntime {
	r := e.war[group]
	if r == nil {
		r = &warRuntime{Started: time.Now(), Suspects: map[string]int{}, Quarantine: map[string]time.Time{}}
		e.war[group] = r
	}
	return r
}
func (e *Engine) resetWarRuntime(group string) {
	e.mu.Lock()
	e.war[group] = &warRuntime{Started: time.Now(), Suspects: map[string]int{}, Quarantine: map[string]time.Time{}}
	e.mu.Unlock()
}
func (e *Engine) addWarRisk(group, mid string, score int) {
	e.mu.Lock()
	e.ensureWarRuntimeLocked(group).Suspects[mid] += score
	e.mu.Unlock()
}

func (e *Engine) recordWarAction(group, action string, err error) {
	_, active := e.warActive(group)
	if !active {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.ensureWarRuntimeLocked(group)
	if err != nil {
		r.Failures++
	}
	switch action {
	case "kick":
		r.Kicks++
	case "invite":
		r.Invites++
	case "cancel":
		r.Cancels++
	case "qr":
		r.QRClosed++
	case "rescue":
		r.Rescues++
	}
}

func (e *Engine) observeWarAuto(group string) {
	w := e.Store.War(group)
	if !w.Auto || w.Enabled {
		return
	}
	e.mu.Lock()
	items := append([]auditEvent(nil), e.audit[group]...)
	e.mu.Unlock()
	cutoff, count := time.Now().Add(-10*time.Second).UnixMilli(), 0
	for _, item := range items {
		if item.At >= cutoff {
			count++
		}
	}
	threshold := 5
	if w.Sensitivity == "low" {
		threshold = 8
	} else if w.Sensitivity == "high" {
		threshold = 3
	}
	if count >= threshold {
		if e.Store.activateWarAuto(group, fmt.Sprintf("%d olay/10s", count)) == nil {
			e.resetWarRuntime(group)
			e.Logger.Printf("war auto activated group=%s events=%d", group, count)
		}
	}
}

func (e *Engine) warStatus(group string) string {
	w, active := e.warActive(group)
	remaining := "-"
	if active {
		remaining = time.Until(time.UnixMilli(w.Until)).Round(time.Second).String()
	}
	return fmt.Sprintf("War active=%t level=%d remaining=%s auto=%t sensitivity=%s lock=%t dryrun=%t whitelist=%d\n%s", active, w.Level, remaining, w.Auto, w.Sensitivity, w.Locked, w.DryRun, len(w.Whitelist), e.warReport(group))
}
func (e *Engine) warReport(group string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.ensureWarRuntimeLocked(group)
	return fmt.Sprintf("War report: kick=%d invite=%d cancel=%d qr=%d rescue=%d error=%d suspects=%d", r.Kicks, r.Invites, r.Cancels, r.QRClosed, r.Rescues, r.Failures, len(r.Suspects))
}
func (e *Engine) sendWarSuspects(ctx context.Context, c *lineclient.Client, group string) error {
	e.mu.Lock()
	r := e.ensureWarRuntimeLocked(group)
	type pair struct {
		mid   string
		score int
	}
	var values []pair
	for mid, score := range r.Suspects {
		values = append(values, pair{mid, score})
	}
	e.mu.Unlock()
	sort.Slice(values, func(i, j int) bool { return values[i].score > values[j].score })
	if len(values) == 0 {
		return e.reply(ctx, c, group, "No war suspects.")
	}
	var mids, suffixes []string
	for _, v := range values {
		mids = append(mids, v.mid)
		suffixes = append(suffixes, fmt.Sprintf("risk=%d", v.score))
	}
	return e.sendMIDMentions(ctx, c, group, "War suspects:", mids, suffixes)
}

func (e *Engine) warProtected(group, mid string) bool {
	w := e.Store.War(group)
	return e.Store.IsBot(mid) || e.Store.Role(group, mid) != RoleUser || contains(w.Whitelist, mid)
}
func (e *Engine) warJoinAction(ctx context.Context, c *lineclient.Client, group, joined string) error {
	w, active := e.warActive(group)
	if !active {
		return nil
	}
	e.mu.Lock()
	r := e.ensureWarRuntimeLocked(group)
	until := r.Quarantine[joined]
	e.mu.Unlock()
	if e.warProtected(group, joined) {
		return nil
	}
	if (w.Level >= 3 || time.Now().Before(until)) && !w.DryRun {
		e.addWarRisk(group, joined, 2)
		return e.kick(ctx, c, group, joined)
	}
	return nil
}
