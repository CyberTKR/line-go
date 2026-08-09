package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/CyberTKR/line-go/e2ee"
	"github.com/CyberTKR/line-go/service"
)

type Chat struct {
	MID      string
	Name     string
	Type     int32
	Members  []string
	Invitees []string
	JoinedAt map[string]int64
	Raw      map[int16]any
}

func (c *Client) GetAllChatMIDs(ctx context.Context) ([]string, error) {
	result, err := c.Talk.GetAllChatMIDs(ctx, c.accessToken(), true, true)
	if err != nil {
		return nil, err
	}
	raw, ok := result.(map[int16]any)
	if !ok {
		return nil, fmt.Errorf("getAllChatMids: unexpected result %T", result)
	}
	seen := make(map[string]struct{})
	var mids []string
	for _, fieldID := range []int16{1, 2} {
		values, _ := raw[fieldID].([]any)
		for _, value := range values {
			mid, _ := value.(string)
			if mid == "" {
				continue
			}
			if _, exists := seen[mid]; exists {
				continue
			}
			seen[mid] = struct{}{}
			mids = append(mids, mid)
		}
	}
	return mids, nil
}

func (c *Client) GetChats(ctx context.Context, mids []string) ([]Chat, error) {
	if mids == nil {
		var err error
		mids, err = c.GetAllChatMIDs(ctx)
		if err != nil {
			return nil, err
		}
	}
	if len(mids) == 0 {
		return nil, nil
	}
	result, err := c.Talk.GetChats(ctx, c.accessToken(), mids, true, true)
	if err != nil {
		return nil, err
	}
	raw, ok := result.(map[int16]any)
	if !ok {
		return nil, fmt.Errorf("getChats: unexpected result %T", result)
	}
	values, _ := raw[1].([]any)
	chats := make([]Chat, 0, len(values))
	for _, value := range values {
		fields, ok := value.(map[int16]any)
		if !ok {
			continue
		}
		chat := Chat{
			MID: stringField(fields, 2), Name: stringField(fields, 6),
			Type: int32(int64Field(fields, 1)), JoinedAt: groupMemberJoinTimes(fields), Raw: fields,
		}
		if members, ok := fields[20].([]any); ok {
			for _, member := range members {
				if memberFields, ok := member.(map[int16]any); ok {
					if mid := stringField(memberFields, 1); mid != "" {
						chat.Members = append(chat.Members, mid)
					}
				}
			}
		}
		if len(chat.Members) == 0 {
			chat.Members = groupMemberMIDs(fields)
		}
		if invitees, ok := fields[21].([]any); ok {
			for _, invitee := range invitees {
				if inviteeFields, ok := invitee.(map[int16]any); ok {
					if mid := stringField(inviteeFields, 1); mid != "" {
						chat.Invitees = append(chat.Invitees, mid)
					}
				}
			}
		}
		chats = append(chats, chat)
	}
	return chats, nil
}

func groupMemberMIDs(chat map[int16]any) []string {
	times := groupMemberJoinTimes(chat)
	result := make([]string, 0, len(times))
	for mid := range times {
		result = append(result, mid)
	}
	return result
}

func groupMemberJoinTimes(chat map[int16]any) map[string]int64 {
	extra, _ := chat[8].(map[int16]any)
	groupExtra, _ := extra[1].(map[int16]any)
	members, _ := groupExtra[4].(map[any]any)
	result := make(map[string]int64, len(members))
	for key, value := range members {
		if mid, ok := key.(string); ok {
			joined, _ := value.(int64)
			result[mid] = joined
		}
	}
	return result
}

func (c *Client) GetMessageBoxes(ctx context.Context) ([]map[int16]any, error) {
	result, err := c.Talk.GetMessageBoxes(ctx, c.accessToken())
	if err != nil {
		return nil, err
	}
	raw, ok := result.(map[int16]any)
	if !ok {
		return nil, fmt.Errorf("getMessageBoxes: unexpected result %T", result)
	}
	values, _ := raw[1].([]any)
	boxes := make([]map[int16]any, 0, len(values))
	for _, value := range values {
		if fields, ok := value.(map[int16]any); ok {
			boxes = append(boxes, fields)
		}
	}
	return boxes, nil
}

func (c *Client) GetPreviousMessages(ctx context.Context, boxID string, deliveredTime, messageID int64, count int32) ([]Message, error) {
	result, err := c.Talk.GetPreviousMessages(ctx, c.accessToken(), boxID, deliveredTime, messageID, count)
	if err != nil {
		return nil, err
	}
	values, ok := result.([]any)
	if !ok {
		return nil, fmt.Errorf("getPreviousMessagesV2WithRequest: unexpected result %T", result)
	}
	messages := make([]Message, 0, len(values))
	for _, value := range values {
		if fields, ok := value.(map[int16]any); ok {
			messages = append(messages, parseMessage(fields))
		}
	}
	return messages, nil
}

func (c *Client) SendMessage(ctx context.Context, to, text string, toType *int32) (Message, error) {
	return c.sendMessageWithMetadata(ctx, to, text, toType, nil)
}

func (c *Client) SendMention(ctx context.Context, to string, names, mids []string, toType *int32) (Message, error) {
	return c.SendMentions(ctx, to, "Okuyanlar:", names, mids, nil, toType)
}

func (c *Client) SendAllMention(ctx context.Context, to string, toType *int32) (Message, error) {
	const metadata = `{"MENTIONEES":[{"S":"0","E":"4","A":"1"}]}`
	return c.sendMessageWithMetadata(ctx, to, "@All ", toType, map[string]string{"MENTION": metadata})
}

func (c *Client) SendMentions(ctx context.Context, to, heading string, names, mids, suffixes []string, toType *int32) (Message, error) {
	if len(names) != len(mids) || len(mids) == 0 {
		return Message{}, fmt.Errorf("mention name/MID list is invalid")
	}
	var text strings.Builder
	text.WriteString(heading)
	type mentionee struct{ S, E, M string }
	document := struct {
		Mentionees []mentionee `json:"MENTIONEES"`
	}{}
	for index, mid := range mids {
		text.WriteString("\n")
		start := len(utf16.Encode([]rune(text.String())))
		label := "@" + names[index]
		text.WriteString(label)
		end := start + len(utf16.Encode([]rune(label)))
		document.Mentionees = append(document.Mentionees, mentionee{S: strconv.Itoa(start), E: strconv.Itoa(end), M: mid})
		if index < len(suffixes) && suffixes[index] != "" {
			text.WriteString(" " + suffixes[index])
		}
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return Message{}, err
	}
	return c.sendMessageWithMetadata(ctx, to, text.String(), toType, map[string]string{"MENTION": string(raw)})
}

func (c *Client) sendMessageWithMetadata(ctx context.Context, to, text string, toType *int32, extra map[string]string) (Message, error) {
	if to == "" || text == "" {
		return Message{}, fmt.Errorf("to and text cannot be empty")
	}
	selected := int32(0)
	if toType != nil {
		selected = *toType
	} else {
		switch to[0] {
		case 'r', 'R':
			selected = 1
		case 'c', 'C':
			selected = 2
		}
	}
	c.messageMu.RLock()
	_, knownEncrypted := c.encrypted[to]
	c.messageMu.RUnlock()
	var result any
	var err error
	if knownEncrypted {
		result, err = c.sendEncrypted(ctx, to, text, selected, extra)
	} else {
		result, err = c.Talk.SendMessageWithMetadata(ctx, c.accessToken(), to, text, selected, extra)
		if err != nil {
			var serviceError *service.Error
			if errors.As(err, &serviceError) {
				if code, ok := serviceError.Code(); ok && code == 82 {
					c.markEncrypted(to)
					result, err = c.sendEncrypted(ctx, to, text, selected, extra)
				}
			}
		}
	}
	if err != nil {
		return Message{}, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return Message{}, fmt.Errorf("sendMessage: unexpected result %T", result)
	}
	message := parseMessage(fields)
	if message.To == "" {
		message.To = to
	}
	if message.Text == "" {
		message.Text = text
	}
	return message, nil
}

func (c *Client) sendEncrypted(ctx context.Context, to, text string, toType int32, extra map[string]string) (any, error) {
	from, metadata, chunks, err := c.E2EE.EncryptText(ctx, to, text)
	if err != nil {
		return nil, err
	}
	for key, value := range extra {
		metadata[key] = value
	}
	return c.Talk.SendEncryptedMessage(ctx, c.accessToken(), from, to, toType, metadata, chunks)
}

func (c *Client) ResolveMessageText(ctx context.Context, message *Message) (string, error) {
	if message == nil {
		return "", nil
	}
	if message.Text != "" {
		return message.Text, nil
	}
	if len(message.Chunks) == 0 {
		return "", nil
	}
	target := message.To
	if message.ToType == 0 && message.To == c.Session.MID && message.From != "" {
		target = message.From
	}
	c.markEncrypted(target)
	text, err := c.E2EE.DecryptText(ctx, e2ee.Message{
		To: message.To, From: message.From, ToType: message.ToType,
		ContentType: message.ContentType, Metadata: message.Metadata, Chunks: message.Chunks,
	})
	if err != nil {
		return "", err
	}
	message.Text = text
	return text, nil
}

func (c *Client) markEncrypted(target string) {
	if target == "" {
		return
	}
	c.messageMu.Lock()
	c.encrypted[target] = struct{}{}
	c.messageMu.Unlock()
}

func (c *Client) AcceptChatInvitation(ctx context.Context, chatMID string) error {
	_, err := c.Talk.AcceptChatInvitation(ctx, c.accessToken(), chatMID)
	return err
}

func (c *Client) LeaveChat(ctx context.Context, chatMID string) error {
	_, err := c.Talk.DeleteSelfFromChat(ctx, c.accessToken(), chatMID)
	return err
}

func (c *Client) CloseChatTicket(ctx context.Context, chatMID string) error {
	_, err := c.Talk.CloseChatTicket(ctx, c.accessToken(), chatMID)
	return err
}

func (c *Client) OpenChatTicket(ctx context.Context, chatMID string) error {
	_, err := c.Talk.OpenChatTicket(ctx, c.accessToken(), chatMID)
	return err
}

func (c *Client) ReissueChatTicket(ctx context.Context, chatMID string) (string, error) {
	result, err := c.Talk.ReissueChatTicket(ctx, c.accessToken(), chatMID)
	if err != nil {
		return "", err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return "", fmt.Errorf("reissueChatTicket: unexpected result %T", result)
	}
	ticket, _ := fields[1].(string)
	if ticket == "" {
		return "", fmt.Errorf("reissueChatTicket: returned an empty ticket")
	}
	return ticket, nil
}

func (c *Client) AcceptChatInvitationByTicket(ctx context.Context, chatMID, ticketID string) error {
	_, err := c.Talk.AcceptChatInvitationByTicket(ctx, c.accessToken(), chatMID, ticketID)
	return err
}

func (c *Client) InviteIntoChat(ctx context.Context, chatMID string, targetMIDs ...string) error {
	_, err := c.Talk.InviteIntoChat(ctx, c.accessToken(), chatMID, targetMIDs)
	return err
}

func (c *Client) KickFromChat(ctx context.Context, chatMID string, targetMIDs ...string) error {
	_, err := c.Talk.DeleteOtherFromChat(ctx, c.accessToken(), chatMID, targetMIDs)
	return err
}

func (c *Client) CancelChatInvitation(ctx context.Context, chatMID string, targetMIDs ...string) error {
	_, err := c.Talk.CancelChatInvitation(ctx, c.accessToken(), chatMID, targetMIDs)
	return err
}
