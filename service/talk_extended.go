package service

import (
	"context"
	"fmt"

	"github.com/CyberTKR/line-go/protocol"
)

type ChatUpdate struct {
	Type                  *int32
	Name                  *string
	PicturePath           *string
	NotificationDisabled  *bool
	FavoriteTimestamp     *int64
	PreventedJoinByTicket *bool
	InvitationTicket      *string
	AddFriendDisabled     *bool
	TicketDisabled        *bool
}

type ChatAnnouncement struct {
	Text                     string
	Link                     string
	Thumbnail                string
	Type                     int32
	DisplayFields            int32
	Replace                  string
	SticonOwnership          string
	PostNotificationMetadata string
}

type ConfigurationRequest struct {
	Revision     *int64
	SIMRegion    string
	PhoneRegion  string
	LocaleRegion string
	Carrier      string
	SyncReason   *int32
}

type FollowTarget struct {
	MID          string
	EncryptedMID string
}

func stringsToValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func int32sToValues(values []int32) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func (t *Talk) GetContact(ctx context.Context, accessToken, mid string) (any, error) {
	return t.service.Call(ctx, "getContact", []protocol.Field{
		protocol.F(2, protocol.String, mid),
	}, accessToken)
}

func (t *Talk) GetContactsV2(ctx context.Context, accessToken string, mids []string, withUserStatus bool, syncReason int32) (any, error) {
	return t.service.Call(ctx, "getContactsV2", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.ListField(1, protocol.String, stringsToValues(mids)),
			protocol.SetField(2, protocol.I32, []any{}),
			protocol.F(3, protocol.Bool, withUserStatus),
		}),
		protocol.F(2, protocol.I32, syncReason),
	}, accessToken)
}

func (t *Talk) GetBlockedContactIDs(ctx context.Context, accessToken string) (any, error) {
	return t.service.Call(ctx, "getBlockedContactIds", nil, accessToken)
}

func (t *Talk) GetBlockedRecommendationIDs(ctx context.Context, accessToken string) (any, error) {
	return t.service.Call(ctx, "getBlockedRecommendationIds", nil, accessToken)
}

func (t *Talk) GetRecommendationIDs(ctx context.Context, accessToken string) (any, error) {
	return t.service.Call(ctx, "getRecommendationIds", nil, accessToken)
}

func (t *Talk) FindAndAddContactByUserID(ctx context.Context, accessToken, userID string) (any, error) {
	return t.service.Call(ctx, "findAndAddContactsByUserid", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, userID),
		protocol.F(3, protocol.String, `{"screen":"friendAdd:idSearch","spec":"native"}`),
	}, accessToken)
}

func (t *Talk) FindContactByUserTicket(ctx context.Context, accessToken, ticket string) (any, error) {
	return t.service.Call(ctx, "findContactByUserTicket", []protocol.Field{
		protocol.F(2, protocol.String, ticket),
	}, accessToken)
}

func (t *Talk) UpdateContactSetting(ctx context.Context, accessToken, mid string, flag int32, value string) (any, error) {
	return t.service.Call(ctx, "updateContactSetting", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, mid),
		protocol.F(3, protocol.I32, flag),
		protocol.F(4, protocol.String, value),
	}, accessToken)
}

func (t *Talk) BlockContact(ctx context.Context, accessToken, mid string) (any, error) {
	return t.service.Call(ctx, "blockContact", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, mid),
	}, accessToken)
}

func (t *Talk) UnblockContact(ctx context.Context, accessToken, mid, reference string) (any, error) {
	fields := []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, mid),
	}
	if reference != "" {
		fields = append(fields, protocol.F(3, protocol.String, reference))
	}
	return t.service.Call(ctx, "unblockContact", fields, accessToken)
}

func (t *Talk) BlockRecommendation(ctx context.Context, accessToken, mid string) (any, error) {
	return t.service.Call(ctx, "blockRecommendation", []protocol.Field{
		protocol.F(2, protocol.String, mid),
	}, accessToken)
}

func (t *Talk) UnblockRecommendation(ctx context.Context, accessToken, mid string) (any, error) {
	return t.service.Call(ctx, "unblockRecommendation", []protocol.Field{
		protocol.F(2, protocol.String, mid),
	}, accessToken)
}

func (t *Talk) GetSettingsAttributes(ctx context.Context, accessToken string, attributes []int32) (any, error) {
	return t.service.Call(ctx, "getSettingsAttributes2", []protocol.Field{
		protocol.SetField(2, protocol.I32, int32sToValues(attributes)),
	}, accessToken)
}

func (t *Talk) GetConfigurations(ctx context.Context, accessToken string, request ConfigurationRequest) (any, error) {
	fields := make([]protocol.Field, 0, 6)
	if request.Revision != nil {
		fields = append(fields, protocol.F(2, protocol.I64, *request.Revision))
	}
	for _, field := range []struct {
		id    int16
		value string
	}{{3, request.SIMRegion}, {4, request.PhoneRegion}, {5, request.LocaleRegion}, {6, request.Carrier}} {
		if field.value != "" {
			fields = append(fields, protocol.F(field.id, protocol.String, field.value))
		}
	}
	if request.SyncReason != nil {
		fields = append(fields, protocol.F(7, protocol.I32, *request.SyncReason))
	}
	return t.service.Call(ctx, "getConfigurations", fields, accessToken)
}

func (t *Talk) UpdateNotificationToken(ctx context.Context, accessToken, token string, tokenType int32) (any, error) {
	return t.service.Call(ctx, "updateNotificationToken", []protocol.Field{
		protocol.F(2, protocol.String, token),
		protocol.F(3, protocol.I32, tokenType),
	}, accessToken)
}

func (t *Talk) AcquireEncryptedAccessToken(ctx context.Context, accessToken string, featureType int32) (any, error) {
	return t.service.Call(ctx, "acquireEncryptedAccessToken", []protocol.Field{
		protocol.F(2, protocol.I32, featureType),
	}, accessToken)
}

func (t *Talk) GetRecentMessages(ctx context.Context, accessToken, chatMID string, count int32) (any, error) {
	return t.service.Call(ctx, "getRecentMessagesV2", []protocol.Field{
		protocol.F(2, protocol.String, chatMID),
		protocol.F(3, protocol.I32, count),
	}, accessToken)
}

func (t *Talk) RequestResendMessage(ctx context.Context, accessToken, senderMID, messageID string) (any, error) {
	return t.service.Call(ctx, "requestResendMessage", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, senderMID),
		protocol.F(3, protocol.String, messageID),
	}, accessToken)
}

func (t *Talk) DetermineMediaMessageFlow(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "determineMediaMessageFlow", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, chatMID),
		}),
	}, accessToken)
}

func (t *Talk) CreateChat(ctx context.Context, accessToken, name string, targetMIDs []string, chatType int32, picturePath string) (any, error) {
	request := []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.I32, chatType),
		protocol.F(3, protocol.String, name),
		protocol.SetField(4, protocol.String, stringsToValues(targetMIDs)),
	}
	if picturePath != "" {
		request = append(request, protocol.F(5, protocol.String, picturePath))
	}
	return t.service.Call(ctx, "createChat", []protocol.Field{
		protocol.F(1, protocol.Struct, request),
	}, accessToken)
}

func (t *Talk) UpdateChat(ctx context.Context, accessToken, chatMID string, updatedAttribute int32, update ChatUpdate) (any, error) {
	chat := []protocol.Field{protocol.F(2, protocol.String, chatMID)}
	if update.Type != nil {
		chat = append(chat, protocol.F(1, protocol.I32, *update.Type))
	}
	if update.NotificationDisabled != nil {
		chat = append(chat, protocol.F(4, protocol.Bool, *update.NotificationDisabled))
	}
	if update.FavoriteTimestamp != nil {
		chat = append(chat, protocol.F(5, protocol.I64, *update.FavoriteTimestamp))
	}
	if update.Name != nil {
		chat = append(chat, protocol.F(6, protocol.String, *update.Name))
	}
	if update.PicturePath != nil {
		chat = append(chat, protocol.F(7, protocol.String, *update.PicturePath))
	}
	group := make([]protocol.Field, 0, 4)
	if update.PreventedJoinByTicket != nil {
		group = append(group, protocol.F(2, protocol.Bool, *update.PreventedJoinByTicket))
	}
	if update.InvitationTicket != nil {
		group = append(group, protocol.F(3, protocol.String, *update.InvitationTicket))
	}
	if update.AddFriendDisabled != nil {
		group = append(group, protocol.F(6, protocol.Bool, *update.AddFriendDisabled))
	}
	if update.TicketDisabled != nil {
		group = append(group, protocol.F(7, protocol.Bool, *update.TicketDisabled))
	}
	if len(group) > 0 {
		chat = append(chat, protocol.F(8, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.Struct, group),
		}))
	}
	return t.service.Call(ctx, "updateChat", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.Struct, chat),
			protocol.F(3, protocol.I32, updatedAttribute),
		}),
	}, accessToken)
}

func (t *Talk) GetRooms(ctx context.Context, accessToken string, roomIDs []string) (any, error) {
	return t.service.Call(ctx, "getRoomsV2", []protocol.Field{
		protocol.ListField(2, protocol.String, stringsToValues(roomIDs)),
	}, accessToken)
}

func (t *Talk) GetChatAnnouncements(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "getChatRoomAnnouncements", []protocol.Field{
		protocol.F(2, protocol.String, chatMID),
	}, accessToken)
}

func (t *Talk) GetChatAnnouncementsBulk(ctx context.Context, accessToken string, chatMIDs []string, syncReason int32) (any, error) {
	return t.service.Call(ctx, "getChatRoomAnnouncementsBulk", []protocol.Field{
		protocol.ListField(2, protocol.String, stringsToValues(chatMIDs)),
		protocol.F(3, protocol.I32, syncReason),
	}, accessToken)
}

func (t *Talk) CreateChatAnnouncement(ctx context.Context, accessToken, chatMID string, announcement ChatAnnouncement) (any, error) {
	contents := []protocol.Field{
		protocol.F(1, protocol.I32, announcement.DisplayFields),
		protocol.F(2, protocol.String, announcement.Text),
		protocol.F(3, protocol.String, announcement.Link),
	}
	if announcement.Thumbnail != "" {
		contents = append(contents, protocol.F(4, protocol.String, announcement.Thumbnail))
	}
	metadata := make([]protocol.Field, 0, 3)
	for _, field := range []struct {
		id    int16
		value string
	}{{1, announcement.Replace}, {2, announcement.SticonOwnership}, {3, announcement.PostNotificationMetadata}} {
		if field.value != "" {
			metadata = append(metadata, protocol.F(field.id, protocol.String, field.value))
		}
	}
	if len(metadata) > 0 {
		contents = append(contents, protocol.F(5, protocol.Struct, metadata))
	}
	return t.service.Call(ctx, "createChatRoomAnnouncement", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, chatMID),
		protocol.F(3, protocol.I32, announcement.Type),
		protocol.F(4, protocol.Struct, contents),
	}, accessToken)
}

func (t *Talk) RemoveChatAnnouncement(ctx context.Context, accessToken, chatMID string, sequence int64) (any, error) {
	return t.service.Call(ctx, "removeChatRoomAnnouncement", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.String, chatMID),
		protocol.F(3, protocol.I64, sequence),
	}, accessToken)
}

func followTargetFields(target FollowTarget) ([]protocol.Field, error) {
	if (target.MID == "") == (target.EncryptedMID == "") {
		return nil, fmt.Errorf("provide exactly one of MID or EncryptedMID")
	}
	if target.MID != "" {
		return []protocol.Field{protocol.F(1, protocol.String, target.MID)}, nil
	}
	return []protocol.Field{protocol.F(2, protocol.String, target.EncryptedMID)}, nil
}

func (t *Talk) followCall(ctx context.Context, method, accessToken string, target FollowTarget) (any, error) {
	targetFields, err := followTargetFields(target)
	if err != nil {
		return nil, err
	}
	return t.service.Call(ctx, method, []protocol.Field{
		protocol.F(2, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.Struct, targetFields),
		}),
	}, accessToken)
}

func (t *Talk) GetFollowers(ctx context.Context, accessToken string, target FollowTarget, cursor string) (any, error) {
	targetFields, err := followTargetFields(target)
	if err != nil {
		return nil, err
	}
	request := []protocol.Field{protocol.F(1, protocol.Struct, targetFields)}
	if cursor != "" {
		request = append(request, protocol.F(2, protocol.String, cursor))
	}
	return t.service.Call(ctx, "getFollowers", []protocol.Field{
		protocol.F(2, protocol.Struct, request),
	}, accessToken)
}

func (t *Talk) GetFollowings(ctx context.Context, accessToken string, target FollowTarget, cursor string) (any, error) {
	targetFields, err := followTargetFields(target)
	if err != nil {
		return nil, err
	}
	request := []protocol.Field{protocol.F(1, protocol.Struct, targetFields)}
	if cursor != "" {
		request = append(request, protocol.F(2, protocol.String, cursor))
	}
	return t.service.Call(ctx, "getFollowings", []protocol.Field{
		protocol.F(2, protocol.Struct, request),
	}, accessToken)
}

func (t *Talk) Follow(ctx context.Context, accessToken string, target FollowTarget) (any, error) {
	return t.followCall(ctx, "follow", accessToken, target)
}

func (t *Talk) Unfollow(ctx context.Context, accessToken string, target FollowTarget) (any, error) {
	return t.followCall(ctx, "unfollow", accessToken, target)
}

func (t *Talk) RemoveFollower(ctx context.Context, accessToken string, target FollowTarget) (any, error) {
	return t.followCall(ctx, "removeFollower", accessToken, target)
}
