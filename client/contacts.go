package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CyberTKR/line-go/service"
)

type Contact struct {
	MID         string
	DisplayName string
}

func (c *Client) GetContacts(ctx context.Context, mids []string) ([]Contact, error) {
	if len(mids) == 0 {
		return nil, nil
	}
	values, err := c.Talk.GetContacts(ctx, c.accessToken(), mids)
	if err != nil {
		return nil, err
	}
	contacts := make([]Contact, 0, len(values))
	for _, value := range values {
		contacts = append(contacts, Contact{MID: value.MID, DisplayName: value.DisplayName})
	}
	return contacts, nil
}

func (c *Client) GetAllContactIDs(ctx context.Context) ([]string, error) {
	result, err := c.Talk.GetAllContactIDs(ctx, c.accessToken())
	if err != nil {
		return nil, err
	}
	values, ok := result.([]any)
	if !ok {
		return nil, fmt.Errorf("getAllContactIds: unexpected result %T", result)
	}
	contacts := make([]string, 0, len(values))
	for _, value := range values {
		if mid, ok := value.(string); ok && mid != "" {
			contacts = append(contacts, mid)
		}
	}
	return contacts, nil
}

func (c *Client) EnsureFriend(ctx context.Context, target string) (bool, error) {
	return c.ensureFriend(ctx, target, "")
}

func (c *Client) EnsureFriendFromGroup(ctx context.Context, target, group string) (bool, error) {
	return c.ensureFriend(ctx, target, group)
}

func (c *Client) ensureFriend(ctx context.Context, target, group string) (bool, error) {
	if target == "" || target == c.Session.MID {
		return false, nil
	}
	c.contactMu.RLock()
	_, cached := c.contacts[target]
	cacheValid := time.Now().Before(c.contactsUntil)
	c.contactMu.RUnlock()
	if cached && cacheValid {
		return false, nil
	}
	if !cacheValid {
		contacts, err := c.GetAllContactIDs(ctx)
		if err != nil {
			return false, err
		}
		c.contactMu.Lock()
		c.contacts = make(map[string]struct{}, len(contacts))
		for _, mid := range contacts {
			c.contacts[mid] = struct{}{}
		}
		c.contactsUntil = time.Now().Add(5 * time.Minute)
		_, cached = c.contacts[target]
		c.contactMu.Unlock()
		if cached {
			return false, nil
		}
	}
	var err error
	if group != "" {
		_, err = c.Talk.AddFriendByMIDFromGroup(ctx, c.accessToken(), target, group)
		var rejected *service.Error
		if errors.As(err, &rejected) {
			if code, ok := rejected.Code(); ok && code == 7 {
				_, err = c.Talk.AddFriendByMID(ctx, c.accessToken(), target)
			}
		}
	} else {
		_, err = c.Talk.AddFriendByMID(ctx, c.accessToken(), target)
	}
	if err != nil {
		return false, err
	}
	c.contactMu.Lock()
	c.contacts[target] = struct{}{}
	c.contactsUntil = time.Now().Add(5 * time.Minute)
	c.contactMu.Unlock()
	return true, nil
}
