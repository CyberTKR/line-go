package client

import (
	"context"
	"fmt"
	"net/url"
)

type UserTicket struct {
	ID             string
	ExpirationTime int64
	MaxUseCount    int32
}

func (ticket UserTicket) URL() string {
	return "https://line.me/ti/p/" + url.PathEscape(ticket.ID)
}

func (c *Client) GenerateUserTicket(ctx context.Context, expirationTime int64, maxUseCount int32) (UserTicket, error) {
	if maxUseCount <= 0 {
		return UserTicket{}, fmt.Errorf("ticket usage count must be positive")
	}
	result, err := c.Talk.GenerateUserTicket(ctx, c.accessToken(), expirationTime, maxUseCount)
	if err != nil {
		return UserTicket{}, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return UserTicket{}, fmt.Errorf("generateUserTicket: unexpected result %T", result)
	}
	ticket := UserTicket{
		ID:             stringField(fields, 1),
		ExpirationTime: int64Field(fields, 10),
		MaxUseCount:    int32(int64Field(fields, 21)),
	}
	if ticket.ID == "" {
		return UserTicket{}, fmt.Errorf("generateUserTicket: returned an empty ticket")
	}
	return ticket, nil
}
