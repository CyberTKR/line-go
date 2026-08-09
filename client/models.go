package client

type Message struct {
	ID          string
	To          string
	From        string
	Text        string
	ToType      int32
	ContentType int32
	Metadata    map[any]any
	Chunks      []any
	Raw         map[int16]any
}

type Operation struct {
	Revision        int64
	CreatedTime     int64
	Type            int32
	TypeName        string
	RequestSequence int32
	Checksum        string
	Status          int32
	Param1          string
	Param2          string
	Param3          string
	Message         *Message
	Raw             map[int16]any
}

var operationNames = map[int32]string{
	0:   "END_OF_OPERATION",
	1:   "UPDATE_PROFILE",
	2:   "NOTIFIED_UPDATE_PROFILE",
	9:   "CREATE_GROUP",
	10:  "UPDATE_GROUP",
	11:  "NOTIFIED_UPDATE_GROUP",
	25:  "SEND_MESSAGE",
	26:  "RECEIVE_MESSAGE",
	40:  "SEND_CHAT_CHECKED",
	42:  "NOTIFIED_FORCE_SYNC",
	55:  "NOTIFIED_READ_MESSAGE",
	66:  "UPDATE_PUBLICKEYCHAIN",
	67:  "NOTIFIED_UPDATE_PUBLICKEYCHAIN",
	72:  "REGISTER_E2EE_PUBLICKEY",
	77:  "NOTIFIED_E2EE_KEY_UPDATE",
	122: "NOTIFIED_UPDATE_CHAT",
	124: "NOTIFIED_INVITE_INTO_CHAT",
	126: "NOTIFIED_CANCEL_CHAT_INVITATION",
	130: "NOTIFIED_ACCEPT_CHAT_INVITATION",
	133: "NOTIFIED_DELETE_OTHER_FROM_CHAT",
}

func OperationName(code int32) string {
	if name := operationNames[code]; name != "" {
		return name
	}
	return "UNKNOWN"
}

func parseOperation(value any) (Operation, bool) {
	raw, ok := value.(map[int16]any)
	if !ok {
		return Operation{}, false
	}
	operation := Operation{
		Revision:        int64Field(raw, 1),
		CreatedTime:     int64Field(raw, 2),
		Type:            int32(int64Field(raw, 3)),
		RequestSequence: int32(int64Field(raw, 4)),
		Checksum:        stringField(raw, 5),
		Status:          int32(int64Field(raw, 7)),
		Param1:          stringField(raw, 10),
		Param2:          stringField(raw, 11),
		Param3:          stringField(raw, 12),
		Raw:             raw,
	}
	operation.TypeName = OperationName(operation.Type)
	if messageRaw, ok := raw[20].(map[int16]any); ok {
		message := parseMessage(messageRaw)
		operation.Message = &message
	}
	return operation, true
}

func parseMessage(raw map[int16]any) Message {
	metadata, _ := raw[18].(map[any]any)
	chunks, _ := raw[20].([]any)
	return Message{
		ID:          stringField(raw, 4),
		To:          stringField(raw, 2),
		From:        stringField(raw, 1),
		Text:        stringField(raw, 10),
		ToType:      int32(int64Field(raw, 3)),
		ContentType: int32(int64Field(raw, 15)),
		Metadata:    metadata,
		Chunks:      chunks,
		Raw:         raw,
	}
}

func stringField(fields map[int16]any, id int16) string {
	value, _ := fields[id].(string)
	return value
}

func int64Field(fields map[int16]any, id int16) int64 {
	value, _ := fields[id].(int64)
	return value
}
