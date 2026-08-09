package guard

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	lineclient "github.com/CyberTKR/line-go/client"
)

type botHealth struct {
	MID         string
	Kick        uint64
	Invite      uint64
	Cancel      uint64
	Success     uint64
	Failures    uint64
	Streak      uint32
	CooldownEnd time.Time
}

type healthPool struct {
	mu   sync.RWMutex
	bots map[string]*botHealth
}

func newHealthPool() *healthPool { return &healthPool{bots: make(map[string]*botHealth)} }

func (p *healthPool) register(mid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bots[mid] == nil {
		p.bots[mid] = &botHealth{MID: mid}
	}
}

func (p *healthPool) record(mid, action string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	value := p.bots[mid]
	if value == nil {
		value = &botHealth{MID: mid}
		p.bots[mid] = value
	}
	switch action {
	case "kick":
		value.Kick++
	case "invite":
		value.Invite++
	case "cancel":
		value.Cancel++
	}
	if err == nil {
		value.Success++
		value.Streak = 0
		return
	}
	value.Failures++
	value.Streak++
	delay := time.Second * time.Duration(1<<min(value.Streak, 6))
	if isLimitError(err) && delay < 30*time.Second {
		delay = 30 * time.Second
	}
	value.CooldownEnd = time.Now().Add(delay)
}

func isLimitError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "429") || strings.Contains(text, "code 35") || strings.Contains(text, "{1:35") ||
		strings.Contains(text, "request blocked") || strings.Contains(text, "rate") || strings.Contains(text, "limit") || strings.Contains(text, "too many")
}

func (p *healthPool) rank(clients []*lineclient.Client) []*lineclient.Client {
	now := time.Now()
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := append([]*lineclient.Client(nil), clients...)
	sort.SliceStable(result, func(i, j int) bool {
		a, b := p.bots[result[i].Session.MID], p.bots[result[j].Session.MID]
		if a == nil || b == nil {
			return a != nil
		}
		aCooling, bCooling := now.Before(a.CooldownEnd), now.Before(b.CooldownEnd)
		if aCooling != bCooling {
			return !aCooling
		}
		if !a.CooldownEnd.Equal(b.CooldownEnd) && aCooling {
			return a.CooldownEnd.Before(b.CooldownEnd)
		}
		aLoad, bLoad := a.Kick+a.Invite+a.Cancel+a.Failures*4, b.Kick+b.Invite+b.Cancel+b.Failures*4
		return aLoad < bLoad
	})
	ready := result[:0]
	for _, current := range result {
		value := p.bots[current.Session.MID]
		if value == nil || !now.Before(value.CooldownEnd) {
			ready = append(ready, current)
		}
	}
	if len(ready) > 0 {
		return ready
	}
	return result
}

func (p *healthPool) report() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	values := make([]*botHealth, 0, len(p.bots))
	for _, value := range p.bots {
		copy := *value
		values = append(values, &copy)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].MID < values[j].MID })
	var output strings.Builder
	output.WriteString("Bot health:")
	for _, value := range values {
		cooldown := "ready"
		if remaining := time.Until(value.CooldownEnd).Round(time.Second); remaining > 0 {
			cooldown = remaining.String()
		}
		fmt.Fprintf(&output, "\n%s kick=%d invite=%d cancel=%d ok=%d err=%d cooldown=%s", value.MID, value.Kick, value.Invite, value.Cancel, value.Success, value.Failures, cooldown)
	}
	return output.String()
}

func (p *healthPool) snapshots() []botHealth {
	p.mu.RLock()
	defer p.mu.RUnlock()
	values := make([]botHealth, 0, len(p.bots))
	for _, value := range p.bots {
		values = append(values, *value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].MID < values[j].MID })
	return values
}
