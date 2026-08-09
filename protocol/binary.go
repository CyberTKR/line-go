package protocol

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	binaryStop   byte = 0
	binaryBool   byte = 2
	binaryByte   byte = 3
	binaryDouble byte = 4
	binaryI16    byte = 6
	binaryI32    byte = 8
	binaryI64    byte = 10
	binaryString byte = 11
	binaryStruct byte = 12
	binaryMap    byte = 13
	binarySet    byte = 14
	binaryList   byte = 15
)

func EncodeBinaryCall(name string, fields []Field, sequenceID uint64) ([]byte, error) {
	w := binaryWriter{data: make([]byte, 0, 256)}
	w.i32(-2147418111)
	w.string(name)
	w.i32(int32(sequenceID))
	if err := w.structValue(fields); err != nil {
		return nil, err
	}
	return w.data, nil
}

func DecodeBinaryMessage(data []byte) (Message, error) {
	r := binaryReader{data: data}
	versionType, err := r.i32()
	if err != nil {
		return Message{}, err
	}
	if uint32(versionType)&0xffff0000 != 0x80010000 {
		return Message{}, fmt.Errorf("binary thrift: unsupported version 0x%x", uint32(versionType))
	}
	name, err := r.string()
	if err != nil {
		return Message{}, err
	}
	sequenceID, err := r.i32()
	if err != nil {
		return Message{}, err
	}
	fields, err := r.structValue()
	if err != nil {
		return Message{}, err
	}
	return Message{Name: name, Type: byte(versionType), SequenceID: uint64(uint32(sequenceID)), Fields: fields}, nil
}

type binaryWriter struct{ data []byte }

func (w *binaryWriter) i16(value int16) {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(value))
	w.data = append(w.data, raw[:]...)
}

func (w *binaryWriter) i32(value int32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(value))
	w.data = append(w.data, raw[:]...)
}

func (w *binaryWriter) i64(value int64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	w.data = append(w.data, raw[:]...)
}

func (w *binaryWriter) string(value string) {
	w.i32(int32(len(value)))
	w.data = append(w.data, value...)
}

func (w *binaryWriter) structValue(fields []Field) error {
	for _, field := range fields {
		fieldType, err := binaryType(field.Kind)
		if err != nil {
			return err
		}
		w.data = append(w.data, fieldType)
		w.i16(field.ID)
		if err := w.value(field.Kind, field.Value, field); err != nil {
			return fmt.Errorf("field %d: %w", field.ID, err)
		}
	}
	w.data = append(w.data, binaryStop)
	return nil
}

func (w *binaryWriter) value(kind Kind, value any, spec Field) error {
	switch kind {
	case Bool:
		boolean, ok := value.(bool)
		if !ok {
			return fmt.Errorf("expected bool, got %T", value)
		}
		if boolean {
			w.data = append(w.data, 1)
		} else {
			w.data = append(w.data, 0)
		}
	case Byte:
		number, err := integer(value)
		if err != nil {
			return err
		}
		w.data = append(w.data, byte(number))
	case I16:
		number, err := integer(value)
		if err != nil {
			return err
		}
		w.i16(int16(number))
	case I32:
		number, err := integer(value)
		if err != nil {
			return err
		}
		w.i32(int32(number))
	case I64:
		number, err := integer(value)
		if err != nil {
			return err
		}
		w.i64(number)
	case Double:
		number, ok := value.(float64)
		if !ok {
			return fmt.Errorf("expected float64, got %T", value)
		}
		w.i64(int64(math.Float64bits(number)))
	case String:
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		w.string(text)
	case Binary:
		raw, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("expected []byte, got %T", value)
		}
		w.i32(int32(len(raw)))
		w.data = append(w.data, raw...)
	case Struct:
		fields, ok := value.([]Field)
		if !ok {
			return fmt.Errorf("expected []protocol.Field, got %T", value)
		}
		return w.structValue(fields)
	case List, Set:
		values, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected []any, got %T", value)
		}
		elementType, err := binaryType(spec.ElementKind)
		if err != nil {
			return err
		}
		w.data = append(w.data, elementType)
		w.i32(int32(len(values)))
		for _, item := range values {
			if err := w.value(spec.ElementKind, item, Field{}); err != nil {
				return err
			}
		}
	case Map:
		values, ok := value.(map[any]any)
		if !ok {
			return fmt.Errorf("expected map[any]any, got %T", value)
		}
		keyType, err := binaryType(spec.KeyKind)
		if err != nil {
			return err
		}
		valueType, err := binaryType(spec.ValueKind)
		if err != nil {
			return err
		}
		w.data = append(w.data, keyType, valueType)
		w.i32(int32(len(values)))
		for key, item := range values {
			if err := w.value(spec.KeyKind, key, Field{}); err != nil {
				return err
			}
			if err := w.value(spec.ValueKind, item, Field{}); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported binary thrift kind %d", kind)
	}
	return nil
}

func binaryType(kind Kind) (byte, error) {
	switch kind {
	case Bool:
		return binaryBool, nil
	case Byte:
		return binaryByte, nil
	case I16:
		return binaryI16, nil
	case I32:
		return binaryI32, nil
	case I64:
		return binaryI64, nil
	case Double:
		return binaryDouble, nil
	case Binary, String:
		return binaryString, nil
	case Struct:
		return binaryStruct, nil
	case Map:
		return binaryMap, nil
	case Set:
		return binarySet, nil
	case List:
		return binaryList, nil
	default:
		return 0, fmt.Errorf("unsupported binary thrift kind %d", kind)
	}
}

type binaryReader struct {
	data []byte
	pos  int
}

func (r *binaryReader) take(size int) ([]byte, error) {
	if size < 0 || r.pos+size > len(r.data) {
		return nil, fmt.Errorf("truncated binary thrift data")
	}
	value := r.data[r.pos : r.pos+size]
	r.pos += size
	return value, nil
}

func (r *binaryReader) i16() (int16, error) {
	raw, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return int16(binary.BigEndian.Uint16(raw)), nil
}

func (r *binaryReader) i32() (int32, error) {
	raw, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(raw)), nil
}

func (r *binaryReader) i64() (int64, error) {
	raw, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(raw)), nil
}

func (r *binaryReader) string() (string, error) {
	raw, err := r.bytes()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (r *binaryReader) bytes() ([]byte, error) {
	size, err := r.i32()
	if err != nil {
		return nil, err
	}
	if size < 0 || size > 64*1024*1024 {
		return nil, fmt.Errorf("invalid binary thrift length %d", size)
	}
	return r.take(int(size))
}

func (r *binaryReader) structValue() (map[int16]any, error) {
	result := make(map[int16]any)
	for {
		rawType, err := r.take(1)
		if err != nil {
			return nil, err
		}
		if rawType[0] == binaryStop {
			return result, nil
		}
		fieldID, err := r.i16()
		if err != nil {
			return nil, err
		}
		value, err := r.value(rawType[0])
		if err != nil {
			return nil, fmt.Errorf("field %d: %w", fieldID, err)
		}
		result[fieldID] = value
	}
}

func (r *binaryReader) value(rawType byte) (any, error) {
	switch rawType {
	case binaryBool:
		raw, err := r.take(1)
		return len(raw) == 1 && raw[0] != 0, err
	case binaryByte:
		raw, err := r.take(1)
		if err != nil {
			return nil, err
		}
		return int8(raw[0]), nil
	case binaryI16:
		return r.i16()
	case binaryI32:
		return r.i32()
	case binaryI64:
		return r.i64()
	case binaryDouble:
		value, err := r.i64()
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(uint64(value)), nil
	case binaryString:
		raw, err := r.bytes()
		if err != nil {
			return nil, err
		}
		if utf8.Valid(raw) {
			return string(raw), nil
		}
		return append([]byte(nil), raw...), nil
	case binaryStruct:
		return r.structValue()
	case binaryMap:
		types, err := r.take(2)
		if err != nil {
			return nil, err
		}
		size, err := r.i32()
		if err != nil {
			return nil, err
		}
		if size < 0 || size > 1_000_000 {
			return nil, fmt.Errorf("invalid map size %d", size)
		}
		values := make(map[any]any, size)
		for range size {
			key, err := r.value(types[0])
			if err != nil {
				return nil, err
			}
			item, err := r.value(types[1])
			if err != nil {
				return nil, err
			}
			values[key] = item
		}
		return values, nil
	case binaryList, binarySet:
		elementType, err := r.take(1)
		if err != nil {
			return nil, err
		}
		size, err := r.i32()
		if err != nil {
			return nil, err
		}
		if size < 0 || size > 1_000_000 {
			return nil, fmt.Errorf("invalid list size %d", size)
		}
		values := make([]any, 0, size)
		for range size {
			item, err := r.value(elementType[0])
			if err != nil {
				return nil, err
			}
			values = append(values, item)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unknown binary thrift type %d", rawType)
	}
}
