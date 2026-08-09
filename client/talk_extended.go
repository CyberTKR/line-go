package client

import (
	"context"
	"fmt"

	"github.com/CyberTKR/line-go/service"
)

func stringListResult(method string, result any) ([]string, error) {
	values, ok := result.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: unexpected result %T", method, result)
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		if item, ok := value.(string); ok && item != "" {
			items = append(items, item)
		}
	}
	return items, nil
}

func (c *Client) GetBlockedContactIDs(ctx context.Context) ([]string, error) {
	result, err := c.Talk.GetBlockedContactIDs(ctx, c.accessToken())
	if err != nil {
		return nil, err
	}
	return stringListResult("getBlockedContactIds", result)
}

func (c *Client) GetBlockedRecommendationIDs(ctx context.Context) ([]string, error) {
	result, err := c.Talk.GetBlockedRecommendationIDs(ctx, c.accessToken())
	if err != nil {
		return nil, err
	}
	return stringListResult("getBlockedRecommendationIds", result)
}

func (c *Client) GetRecommendationIDs(ctx context.Context) ([]string, error) {
	result, err := c.Talk.GetRecommendationIDs(ctx, c.accessToken())
	if err != nil {
		return nil, err
	}
	return stringListResult("getRecommendationIds", result)
}

func (c *Client) AddFriendByUserID(ctx context.Context, userID string) (any, error) {
	return c.Talk.FindAndAddContactByUserID(ctx, c.accessToken(), userID)
}

func (c *Client) FindContactByUserTicket(ctx context.Context, ticket string) (any, error) {
	return c.Talk.FindContactByUserTicket(ctx, c.accessToken(), ticket)
}

func (c *Client) UpdateContactSetting(ctx context.Context, mid string, flag int32, value string) error {
	_, err := c.Talk.UpdateContactSetting(ctx, c.accessToken(), mid, flag, value)
	return err
}

func (c *Client) BlockContact(ctx context.Context, mid string) error {
	_, err := c.Talk.BlockContact(ctx, c.accessToken(), mid)
	return err
}

func (c *Client) UnblockContact(ctx context.Context, mid, reference string) error {
	_, err := c.Talk.UnblockContact(ctx, c.accessToken(), mid, reference)
	return err
}

func (c *Client) BlockRecommendation(ctx context.Context, mid string) error {
	_, err := c.Talk.BlockRecommendation(ctx, c.accessToken(), mid)
	return err
}

func (c *Client) UnblockRecommendation(ctx context.Context, mid string) error {
	_, err := c.Talk.UnblockRecommendation(ctx, c.accessToken(), mid)
	return err
}

func (c *Client) GetSettingsAttributes(ctx context.Context, attributes []int32) (any, error) {
	return c.Talk.GetSettingsAttributes(ctx, c.accessToken(), attributes)
}

func (c *Client) GetConfigurations(ctx context.Context, request service.ConfigurationRequest) (any, error) {
	return c.Talk.GetConfigurations(ctx, c.accessToken(), request)
}

func (c *Client) UpdateNotificationToken(ctx context.Context, token string, tokenType int32) error {
	_, err := c.Talk.UpdateNotificationToken(ctx, c.accessToken(), token, tokenType)
	return err
}

func (c *Client) AcquireEncryptedAccessToken(ctx context.Context, featureType int32) (any, error) {
	return c.Talk.AcquireEncryptedAccessToken(ctx, c.accessToken(), featureType)
}

func (c *Client) GetRecentMessages(ctx context.Context, chatMID string, count int32) ([]Message, error) {
	if count <= 0 {
		return nil, nil
	}
	result, err := c.Talk.GetRecentMessages(ctx, c.accessToken(), chatMID, count)
	if err != nil {
		return nil, err
	}
	values, ok := result.([]any)
	if !ok {
		return nil, fmt.Errorf("getRecentMessagesV2: unexpected result %T", result)
	}
	messages := make([]Message, 0, len(values))
	for _, value := range values {
		if fields, ok := value.(map[int16]any); ok {
			messages = append(messages, parseMessage(fields))
		}
	}
	return messages, nil
}

func (c *Client) RequestResendMessage(ctx context.Context, senderMID, messageID string) error {
	_, err := c.Talk.RequestResendMessage(ctx, c.accessToken(), senderMID, messageID)
	return err
}

func (c *Client) DetermineMediaMessageFlow(ctx context.Context, chatMID string) (any, error) {
	return c.Talk.DetermineMediaMessageFlow(ctx, c.accessToken(), chatMID)
}

func (c *Client) CreateChat(ctx context.Context, name string, targetMIDs []string, chatType int32, picturePath string) (Chat, error) {
	result, err := c.Talk.CreateChat(ctx, c.accessToken(), name, targetMIDs, chatType, picturePath)
	if err != nil {
		return Chat{}, err
	}
	raw, ok := result.(map[int16]any)
	if !ok {
		return Chat{}, fmt.Errorf("createChat: unexpected result %T", result)
	}
	if nested, ok := raw[1].(map[int16]any); ok {
		raw = nested
	}
	return chatFromFields(raw), nil
}

func chatFromFields(fields map[int16]any) Chat {
	return Chat{
		MID:      stringField(fields, 2),
		Name:     stringField(fields, 6),
		Type:     int32(int64Field(fields, 1)),
		Members:  groupMemberMIDs(fields),
		JoinedAt: groupMemberJoinTimes(fields),
		Raw:      fields,
	}
}

func (c *Client) UpdateChat(ctx context.Context, chatMID string, updatedAttribute int32, update service.ChatUpdate) error {
	_, err := c.Talk.UpdateChat(ctx, c.accessToken(), chatMID, updatedAttribute, update)
	return err
}

func (c *Client) UpdateChatName(ctx context.Context, chatMID, name string) error {
	return c.UpdateChat(ctx, chatMID, 1, service.ChatUpdate{Name: &name})
}

func (c *Client) UpdateChatTicket(ctx context.Context, chatMID string, enabled bool) error {
	prevented := !enabled
	return c.UpdateChat(ctx, chatMID, 4, service.ChatUpdate{PreventedJoinByTicket: &prevented})
}

func (c *Client) GetRooms(ctx context.Context, roomIDs []string) (any, error) {
	return c.Talk.GetRooms(ctx, c.accessToken(), roomIDs)
}

func (c *Client) GetChatAnnouncements(ctx context.Context, chatMID string) (any, error) {
	return c.Talk.GetChatAnnouncements(ctx, c.accessToken(), chatMID)
}

func (c *Client) GetChatAnnouncementsBulk(ctx context.Context, chatMIDs []string) (any, error) {
	return c.Talk.GetChatAnnouncementsBulk(ctx, c.accessToken(), chatMIDs, 2)
}

func (c *Client) CreateChatAnnouncement(ctx context.Context, chatMID, text, link string) (any, error) {
	return c.Talk.CreateChatAnnouncement(ctx, c.accessToken(), chatMID, service.ChatAnnouncement{
		Text: text, Link: link, DisplayFields: 5,
	})
}

func (c *Client) RemoveChatAnnouncement(ctx context.Context, chatMID string, sequence int64) error {
	_, err := c.Talk.RemoveChatAnnouncement(ctx, c.accessToken(), chatMID, sequence)
	return err
}

func (c *Client) GetFollowers(ctx context.Context, target service.FollowTarget, cursor string) (any, error) {
	return c.Talk.GetFollowers(ctx, c.accessToken(), target, cursor)
}

func (c *Client) GetFollowings(ctx context.Context, target service.FollowTarget, cursor string) (any, error) {
	return c.Talk.GetFollowings(ctx, c.accessToken(), target, cursor)
}

func (c *Client) Follow(ctx context.Context, target service.FollowTarget) error {
	_, err := c.Talk.Follow(ctx, c.accessToken(), target)
	return err
}

func (c *Client) Unfollow(ctx context.Context, target service.FollowTarget) error {
	_, err := c.Talk.Unfollow(ctx, c.accessToken(), target)
	return err
}

func (c *Client) RemoveFollower(ctx context.Context, target service.FollowTarget) error {
	_, err := c.Talk.RemoveFollower(ctx, c.accessToken(), target)
	return err
}
