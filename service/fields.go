package service

func stringField(fields map[int16]any, id int16) string {
	value, _ := fields[id].(string)
	return value
}

func int64Field(fields map[int16]any, id int16) int64 {
	switch value := fields[id].(type) {
	case int64:
		return value
	case int32:
		return int64(value)
	case int16:
		return int64(value)
	case int8:
		return int64(value)
	default:
		return 0
	}
}
