package service

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/CyberTKR/line-go/api"
	"github.com/CyberTKR/line-go/protocol"
	"github.com/CyberTKR/line-go/transport"
)

type Profile struct {
	MID           string
	DisplayName   string
	StatusMessage string
	Raw           map[int16]any
}

type Contact struct {
	MID         string
	DisplayName string
	Raw         map[int16]any
}

type Talk struct {
	service   *Service
	sync      *Service
	relation  *Service
	requestID atomic.Int32
}

func NewTalk(client *transport.Client) *Talk {
	return &Talk{
		service:  New(client, api.TalkPath),
		sync:     New(client, api.SyncPath),
		relation: New(client, api.RelationPath),
	}
}

func (t *Talk) SetAccessToken(token string) {
	t.service.SetAccessToken(token)
	t.sync.SetAccessToken(token)
	t.relation.SetAccessToken(token)
}

func (t *Talk) SetTokenRefresher(refresh func(context.Context, string) (string, error)) {
	t.service.SetTokenRefresher(refresh)
	t.sync.SetTokenRefresher(refresh)
	t.relation.SetTokenRefresher(refresh)
}

func (t *Talk) GetAllContactIDs(ctx context.Context, accessToken string) (any, error) {
	return t.service.Call(ctx, "getAllContactIds", []protocol.Field{
		protocol.F(1, protocol.I32, int32(1)),
	}, accessToken)
}

func (t *Talk) GetLastOpRevision(ctx context.Context, accessToken string) (int64, error) {
	result, err := t.service.Call(ctx, "getLastOpRevision", nil, accessToken)
	if err != nil {
		return 0, err
	}
	revision, ok := result.(int64)
	if !ok {
		return 0, fmt.Errorf("getLastOpRevision: unexpected result %T", result)
	}
	return revision, nil
}

func (t *Talk) GetContacts(ctx context.Context, accessToken string, mids []string) ([]Contact, error) {
	values := make([]any, len(mids))
	for index, mid := range mids {
		values[index] = mid
	}
	result, err := t.service.Call(ctx, "getContacts", []protocol.Field{
		protocol.ListField(2, protocol.String, values),
	}, accessToken)
	if err != nil {
		return nil, err
	}
	rawContacts, ok := result.([]any)
	if !ok {
		return nil, fmt.Errorf("getContacts: unexpected result %T", result)
	}
	contacts := make([]Contact, 0, len(rawContacts))
	for _, value := range rawContacts {
		raw, ok := value.(map[int16]any)
		if !ok {
			continue
		}
		contacts = append(contacts, Contact{MID: stringField(raw, 1), DisplayName: stringField(raw, 22), Raw: raw})
	}
	return contacts, nil
}

func (t *Talk) AddFriendByMID(ctx context.Context, accessToken, mid string) (any, error) {
	return t.addFriendByMID(ctx, accessToken, mid, "")
}

func (t *Talk) AddFriendByMIDFromGroup(ctx context.Context, accessToken, mid, chatMID string) (any, error) {
	return t.addFriendByMID(ctx, accessToken, mid, chatMID)
}

func (t *Talk) addFriendByMID(ctx context.Context, accessToken, mid, chatMID string) (any, error) {
	reference := `{"screen":"friendAdd:recommend","spec":"native"}`
	trackingMeta := []protocol.Field{
		protocol.F(10, protocol.Struct, []protocol.Field{}),
	}
	if chatMID != "" {
		reference = `{"screen":"groupMemberList","spec":"native"}`
		trackingMeta = []protocol.Field{
			protocol.F(5, protocol.Struct, []protocol.Field{
				protocol.F(1, protocol.String, chatMID),
			}),
		}
	}
	return t.relation.Call(ctx, "addFriendByMid", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.String, mid),
			protocol.F(3, protocol.Struct, []protocol.Field{
				protocol.F(1, protocol.String, reference),
				protocol.F(2, protocol.Struct, trackingMeta),
			}),
		}),
	}, accessToken)
}

func (t *Talk) GetProfile(ctx context.Context, accessToken string) (Profile, error) {
	result, err := t.service.Call(ctx, "getProfile", []protocol.Field{
		protocol.F(1, protocol.I32, int32(2)),
	}, accessToken)
	if err != nil {
		return Profile{}, err
	}
	raw, ok := result.(map[int16]any)
	if !ok {
		return Profile{}, fmt.Errorf("getProfile: unexpected result %T", result)
	}
	return Profile{
		MID:           stringField(raw, 1),
		DisplayName:   stringField(raw, 20),
		StatusMessage: stringField(raw, 24),
		Raw:           raw,
	}, nil
}

func (t *Talk) GenerateUserTicket(ctx context.Context, accessToken string, expirationTime int64, maxUseCount int32) (any, error) {
	return t.service.Call(ctx, "generateUserTicket", []protocol.Field{
		protocol.F(3, protocol.I64, expirationTime),
		protocol.F(4, protocol.I32, maxUseCount),
	}, accessToken)
}

func (t *Talk) Sync(ctx context.Context, accessToken string, revision int64, count int32, globalRevision, individualRevision int64) (any, error) {
	return t.sync.Call(ctx, "sync", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I64, revision),
			protocol.F(2, protocol.I32, count),
			protocol.F(3, protocol.I64, globalRevision),
			protocol.F(4, protocol.I64, individualRevision),
		}),
	}, accessToken)
}

func (t *Talk) GetAllChatMIDs(ctx context.Context, accessToken string, withMembers, withInvitees bool) (any, error) {
	return t.service.Call(ctx, "getAllChatMids", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.Bool, withMembers),
			protocol.F(2, protocol.Bool, withInvitees),
		}),
		protocol.F(2, protocol.I32, int32(2)),
	}, accessToken)
}

func (t *Talk) GetChats(ctx context.Context, accessToken string, mids []string, withMembers, withInvitees bool) (any, error) {
	values := make([]any, len(mids))
	for index, mid := range mids {
		values[index] = mid
	}
	return t.service.Call(ctx, "getChats", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.ListField(1, protocol.String, values),
			protocol.F(2, protocol.Bool, withMembers),
			protocol.F(3, protocol.Bool, withInvitees),
		}),
		protocol.F(2, protocol.I32, int32(1)),
	}, accessToken)
}

func (t *Talk) GetMessageBoxes(ctx context.Context, accessToken string) (any, error) {
	return t.service.Call(ctx, "getMessageBoxes", []protocol.Field{
		protocol.F(2, protocol.Struct, []protocol.Field{
			protocol.F(3, protocol.Bool, true),
			protocol.F(4, protocol.I32, int32(100)),
			protocol.F(5, protocol.Bool, true),
			protocol.F(6, protocol.I32, int32(0)),
		}),
		protocol.F(3, protocol.I32, int32(2)),
	}, accessToken)
}

func (t *Talk) GetPreviousMessages(ctx context.Context, accessToken, boxID string, deliveredTime, messageID int64, count int32) (any, error) {
	return t.service.Call(ctx, "getPreviousMessagesV2WithRequest", []protocol.Field{
		protocol.F(2, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.String, boxID),
			protocol.F(2, protocol.Struct, []protocol.Field{
				protocol.F(1, protocol.I64, deliveredTime),
				protocol.F(2, protocol.I64, messageID),
			}),
			protocol.F(3, protocol.I32, count),
		}),
		protocol.F(3, protocol.I32, int32(2)),
	}, accessToken)
}

func (t *Talk) SendMessage(ctx context.Context, accessToken, to, text string, toType int32) (any, error) {
	return t.sendMessage(ctx, accessToken, to, text, toType, "", nil, nil)
}

func (t *Talk) SendMessageWithMetadata(ctx context.Context, accessToken, to, text string, toType int32, metadata map[string]string) (any, error) {
	return t.sendMessage(ctx, accessToken, to, text, toType, "", metadata, nil)
}

func (t *Talk) SendEncryptedMessage(ctx context.Context, accessToken, from, to string, toType int32, metadata map[string]string, chunks [][]byte) (any, error) {
	return t.sendMessage(ctx, accessToken, to, "", toType, from, metadata, chunks)
}

func (t *Talk) sendMessage(ctx context.Context, accessToken, to, text string, toType int32, from string, metadata map[string]string, chunks [][]byte) (any, error) {
	metadataValues := make(map[any]any, len(metadata))
	for key, value := range metadata {
		metadataValues[key] = value
	}
	message := []protocol.Field{
		protocol.F(2, protocol.String, to),
		protocol.F(3, protocol.I32, toType),
		protocol.F(5, protocol.I64, int64(0)),
		protocol.F(6, protocol.I64, int64(0)),
		protocol.F(14, protocol.Bool, false),
		protocol.F(15, protocol.I32, int32(0)),
		protocol.MapField(18, protocol.String, protocol.String, metadataValues),
		protocol.F(19, protocol.Byte, int8(0)),
	}
	if from != "" {
		message = append([]protocol.Field{protocol.F(1, protocol.String, from)}, message...)
	}
	if len(chunks) == 0 {
		message = append(message[:4], append([]protocol.Field{protocol.F(10, protocol.String, text)}, message[4:]...)...)
	} else {
		values := make([]any, len(chunks))
		for index, chunk := range chunks {
			values[index] = chunk
		}
		message = append(message, protocol.ListField(20, protocol.Binary, values))
	}
	return t.service.Call(ctx, "sendMessage", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.Struct, message),
	}, accessToken)
}

func (t *Talk) GetE2EEPublicKey(ctx context.Context, accessToken, mid string, keyVersion, keyID int32) (any, error) {
	return t.service.Call(ctx, "getE2EEPublicKey", []protocol.Field{
		protocol.F(2, protocol.String, mid),
		protocol.F(3, protocol.I32, keyVersion),
		protocol.F(4, protocol.I32, keyID),
	}, accessToken)
}

func (t *Talk) NegotiateE2EEPublicKey(ctx context.Context, accessToken, mid string) (any, error) {
	return t.service.Call(ctx, "negotiateE2EEPublicKey", []protocol.Field{
		protocol.F(2, protocol.String, mid),
	}, accessToken)
}

func (t *Talk) RegisterE2EEPublicKey(ctx context.Context, accessToken string, publicKey []byte) (any, error) {
	return t.service.Call(ctx, "registerE2EEPublicKey", []protocol.Field{
		protocol.F(1, protocol.I32, t.requestID.Add(1)),
		protocol.F(2, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, int32(1)),
			protocol.F(2, protocol.I32, int32(0)),
			protocol.F(4, protocol.Binary, publicKey),
			protocol.F(5, protocol.I64, int64(0)),
		}),
	}, accessToken)
}

func (t *Talk) GetLastE2EEGroupSharedKey(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "getLastE2EEGroupSharedKey", []protocol.Field{
		protocol.F(2, protocol.I32, int32(2)),
		protocol.F(3, protocol.String, chatMID),
	}, accessToken)
}

func (t *Talk) GetE2EEGroupSharedKey(ctx context.Context, accessToken, chatMID string, groupKeyID int32) (any, error) {
	return t.service.Call(ctx, "getE2EEGroupSharedKey", []protocol.Field{
		protocol.F(2, protocol.I32, int32(2)),
		protocol.F(3, protocol.String, chatMID),
		protocol.F(4, protocol.I32, groupKeyID),
	}, accessToken)
}

func (t *Talk) GetLastE2EEPublicKeys(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "getLastE2EEPublicKeys", []protocol.Field{
		protocol.F(2, protocol.String, chatMID),
	}, accessToken)
}

func (t *Talk) RegisterE2EEGroupKey(ctx context.Context, accessToken, chatMID string, members []string, keyIDs []int32, encryptedSharedKeys [][]byte) (any, error) {
	memberValues := make([]any, len(members))
	keyIDValues := make([]any, len(keyIDs))
	encryptedValues := make([]any, len(encryptedSharedKeys))
	for index := range members {
		memberValues[index] = members[index]
		keyIDValues[index] = keyIDs[index]
		encryptedValues[index] = encryptedSharedKeys[index]
	}
	return t.service.Call(ctx, "registerE2EEGroupKey", []protocol.Field{
		protocol.F(2, protocol.I32, int32(1)),
		protocol.F(3, protocol.String, chatMID),
		protocol.ListField(4, protocol.String, memberValues),
		protocol.ListField(5, protocol.I32, keyIDValues),
		protocol.ListField(6, protocol.Binary, encryptedValues),
	}, accessToken)
}

func (t *Talk) AcceptChatInvitation(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "acceptChatInvitation", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.String, chatMID),
		}),
	}, accessToken)
}

func (t *Talk) DeleteSelfFromChat(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "deleteSelfFromChat", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.String, chatMID),
			protocol.F(3, protocol.I64, int64(0)),
			protocol.F(4, protocol.String, ""),
			protocol.F(5, protocol.I64, int64(0)),
			protocol.F(6, protocol.String, ""),
		}),
	}, accessToken)
}

func (t *Talk) CloseChatTicket(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.setChatTicketJoin(ctx, accessToken, chatMID, true)
}

func (t *Talk) OpenChatTicket(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.setChatTicketJoin(ctx, accessToken, chatMID, false)
}

func (t *Talk) setChatTicketJoin(ctx context.Context, accessToken, chatMID string, prevented bool) (any, error) {
	return t.service.Call(ctx, "updateChat", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.Struct, []protocol.Field{
				protocol.F(2, protocol.String, chatMID),
				protocol.F(8, protocol.Struct, []protocol.Field{
					protocol.F(1, protocol.Struct, []protocol.Field{protocol.F(2, protocol.Bool, prevented)}),
				}),
			}),
			protocol.F(3, protocol.I32, int32(4)),
		}),
	}, accessToken)
}

func (t *Talk) ReissueChatTicket(ctx context.Context, accessToken, chatMID string) (any, error) {
	return t.service.Call(ctx, "reissueChatTicket", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.String, chatMID),
		}),
	}, accessToken)
}

func (t *Talk) AcceptChatInvitationByTicket(ctx context.Context, accessToken, chatMID, ticketID string) (any, error) {
	return t.service.Call(ctx, "acceptChatInvitationByTicket", []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.String, chatMID),
			protocol.F(3, protocol.String, ticketID),
		}),
	}, accessToken)
}

func (t *Talk) InviteIntoChat(ctx context.Context, accessToken, chatMID string, targetMIDs []string) (any, error) {
	return t.chatMembersCall(ctx, "inviteIntoChat", accessToken, chatMID, targetMIDs)
}

func (t *Talk) DeleteOtherFromChat(ctx context.Context, accessToken, chatMID string, targetMIDs []string) (any, error) {
	return t.chatMembersCall(ctx, "deleteOtherFromChat", accessToken, chatMID, targetMIDs)
}

func (t *Talk) CancelChatInvitation(ctx context.Context, accessToken, chatMID string, targetMIDs []string) (any, error) {
	return t.chatMembersCall(ctx, "cancelChatInvitation", accessToken, chatMID, targetMIDs)
}

func (t *Talk) chatMembersCall(ctx context.Context, method, accessToken, chatMID string, targetMIDs []string) (any, error) {
	values := make([]any, 0, len(targetMIDs))
	seen := make(map[string]struct{}, len(targetMIDs))
	for _, mid := range targetMIDs {
		if mid == "" {
			continue
		}
		if _, exists := seen[mid]; exists {
			continue
		}
		seen[mid] = struct{}{}
		values = append(values, mid)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s: target MID is required", method)
	}
	return t.service.Call(ctx, method, []protocol.Field{
		protocol.F(1, protocol.Struct, []protocol.Field{
			protocol.F(1, protocol.I32, t.requestID.Add(1)),
			protocol.F(2, protocol.String, chatMID),
			protocol.SetField(3, protocol.String, values),
		}),
	}, accessToken)
}
