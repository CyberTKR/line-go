package protocol

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	compactStop byte = iota
	compactTrue
	compactFalse
	compactByte
	compactI16
	compactI32
	compactI64
	compactDouble
	compactBinary
	compactList
	compactSet
	compactMap
	compactStruct
)

type Kind byte

const (
	Bool Kind = iota
	Byte
	I16
	I32
	I64
	Double
	Binary
	String
	List
	Set
	Map
	Struct
)

type Field struct {
	ID          int16
	Kind        Kind
	Value       any
	ElementKind Kind
	KeyKind     Kind
	ValueKind   Kind
}

type Message struct {
	Name       string
	Type       byte
	SequenceID uint64
	Fields     map[int16]any
}

func F(id int16, kind Kind, value any) Field {
	return Field{ID: id, Kind: kind, Value: value}
}

func ListField(id int16, elementKind Kind, value any) Field {
	return Field{ID: id, Kind: List, Value: value, ElementKind: elementKind}
}

func SetField(id int16, elementKind Kind, value any) Field {
	return Field{ID: id, Kind: Set, Value: value, ElementKind: elementKind}
}

func MapField(id int16, keyKind, valueKind Kind, value any) Field {
	return Field{ID: id, Kind: Map, Value: value, KeyKind: keyKind, ValueKind: valueKind}
}

func EncodeCall(name string, fields []Field, sequenceID uint64) ([]byte, error) {
	w := writer{data: make([]byte, 0, 128)}
	w.data = append(w.data, 0x82, 0x21)
	w.varint(sequenceID)
	w.binary([]byte(name))
	if err := w.structValue(fields); err != nil {
		return nil, err
	}
	return w.data, nil
}

func DecodeMessage(data []byte) (Message, error) {
	r := reader{data: data}
	protocolID, err := r.byte()
	if err != nil {
		return Message{}, err
	}
	if protocolID != 0x82 {
		return Message{}, fmt.Errorf("compact thrift: expected protocol ID 0x82")
	}
	versionType, err := r.byte()
	if err != nil {
		return Message{}, err
	}
	if versionType&0x1f != 1 {
		return Message{}, fmt.Errorf("compact thrift: unsupported version %d", versionType&0x1f)
	}
	sequenceID, err := r.varint()
	if err != nil {
		return Message{}, err
	}
	name, err := r.binary()
	if err != nil {
		return Message{}, err
	}
	fields, err := r.structValue()
	if err != nil {
		return Message{}, err
	}
	return Message{Name: string(name), Type: versionType >> 5, SequenceID: sequenceID, Fields: fields}, nil
}

func DecodeStruct(data []byte) (map[int16]any, error) {
	r := reader{data: data}
	return r.structValue()
}

type writer struct{ data []byte }

func (w *writer) varint(value uint64) {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		w.data = append(w.data, b)
		if value == 0 {
			return
		}
	}
}

func (w *writer) signed(value int64) { w.varint(uint64(value<<1) ^ uint64(value>>63)) }

func (w *writer) binary(value []byte) {
	w.varint(uint64(len(value)))
	w.data = append(w.data, value...)
}

func (w *writer) structValue(fields []Field) error {
	var previous int16
	for _, field := range fields {
		ctype, err := compactType(field.Kind)
		if err != nil {
			return err
		}
		if field.Kind == Bool {
			if value, ok := field.Value.(bool); ok && !value {
				ctype = compactFalse
			} else {
				ctype = compactTrue
			}
		}
		delta := field.ID - previous
		if delta > 0 && delta <= 15 {
			w.data = append(w.data, byte(delta<<4)|ctype)
		} else {
			w.data = append(w.data, ctype)
			w.signed(int64(field.ID))
		}
		if field.Kind != Bool {
			if err := w.value(field.Kind, field.Value, field); err != nil {
				return fmt.Errorf("field %d: %w", field.ID, err)
			}
		}
		previous = field.ID
	}
	w.data = append(w.data, compactStop)
	return nil
}

func (w *writer) value(kind Kind, value any, spec Field) error {
	switch kind {
	case Bool:
		boolean, ok := value.(bool)
		if !ok {
			return fmt.Errorf("expected bool value")
		}
		if boolean {
			w.data = append(w.data, compactTrue)
		} else {
			w.data = append(w.data, compactFalse)
		}
	case Byte:
		number, err := integer(value)
		if err != nil {
			return err
		}
		w.data = append(w.data, byte(int8(number)))
	case I16, I32, I64:
		number, err := integer(value)
		if err != nil {
			return err
		}
		w.signed(number)
	case Double:
		number, ok := value.(float64)
		if !ok {
			return fmt.Errorf("expected float64 value")
		}
		var raw [8]byte
		binary.LittleEndian.PutUint64(raw[:], math.Float64bits(number))
		w.data = append(w.data, raw[:]...)
	case String:
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string value")
		}
		w.binary([]byte(text))
	case Binary:
		raw, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("expected []byte value")
		}
		w.binary(raw)
	case Struct:
		fields, ok := value.([]Field)
		if !ok {
			return fmt.Errorf("expected []protocol.Field value")
		}
		return w.structValue(fields)
	case List, Set:
		values, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected []any value")
		}
		ctype, err := compactType(spec.ElementKind)
		if err != nil {
			return err
		}
		if len(values) <= 14 {
			w.data = append(w.data, byte(len(values)<<4)|ctype)
		} else {
			w.data = append(w.data, 0xf0|ctype)
			w.varint(uint64(len(values)))
		}
		for _, item := range values {
			if err := w.value(spec.ElementKind, item, Field{}); err != nil {
				return err
			}
		}
	case Map:
		values, ok := value.(map[any]any)
		if !ok {
			return fmt.Errorf("expected map[any]any value")
		}
		w.varint(uint64(len(values)))
		if len(values) > 0 {
			keyType, err := compactType(spec.KeyKind)
			if err != nil {
				return err
			}
			valueType, err := compactType(spec.ValueKind)
			if err != nil {
				return err
			}
			w.data = append(w.data, keyType<<4|valueType)
			for key, item := range values {
				if err := w.value(spec.KeyKind, key, Field{}); err != nil {
					return err
				}
				if err := w.value(spec.ValueKind, item, Field{}); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("unsupported thrift type %d", kind)
	}
	return nil
}

func compactType(kind Kind) (byte, error) {
	switch kind {
	case Bool:
		return compactTrue, nil
	case Byte:
		return compactByte, nil
	case I16:
		return compactI16, nil
	case I32:
		return compactI32, nil
	case I64:
		return compactI64, nil
	case Double:
		return compactDouble, nil
	case Binary, String:
		return compactBinary, nil
	case List:
		return compactList, nil
	case Set:
		return compactSet, nil
	case Map:
		return compactMap, nil
	case Struct:
		return compactStruct, nil
	default:
		return 0, fmt.Errorf("unsupported thrift type %d", kind)
	}
}

func integer(value any) (int64, error) {
	switch number := value.(type) {
	case int:
		return int64(number), nil
	case int8:
		return int64(number), nil
	case int16:
		return int64(number), nil
	case int32:
		return int64(number), nil
	case int64:
		return number, nil
	default:
		return 0, fmt.Errorf("expected integer value, got %T", value)
	}
}

type reader struct {
	data []byte
	pos  int
}

func (r *reader) take(size int) ([]byte, error) {
	if size < 0 || r.pos+size > len(r.data) {
		return nil, fmt.Errorf("eksik compact thrift verisi")
	}
	value := r.data[r.pos : r.pos+size]
	r.pos += size
	return value, nil
}

func (r *reader) byte() (byte, error) {
	value, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (r *reader) varint() (uint64, error) {
	var value uint64
	for shift := uint(0); shift <= 63; shift += 7 {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("invalid varint")
}

func (r *reader) signed() (int64, error) {
	value, err := r.varint()
	if err != nil {
		return 0, err
	}
	return int64(value>>1) ^ -int64(value&1), nil
}

func (r *reader) binary() ([]byte, error) {
	size, err := r.varint()
	if err != nil {
		return nil, err
	}
	if size > uint64(len(r.data)-r.pos) {
		return nil, fmt.Errorf("invalid binary length %d", size)
	}
	return r.take(int(size))
}

func (r *reader) structValue() (map[int16]any, error) {
	result := make(map[int16]any)
	var previous int16
	for {
		header, err := r.byte()
		if err != nil {
			return nil, err
		}
		if header == compactStop {
			return result, nil
		}
		delta, ctype := int16(header>>4), header&0x0f
		fieldID := previous + delta
		if delta == 0 {
			signed, err := r.signed()
			if err != nil {
				return nil, err
			}
			fieldID = int16(signed)
		}
		value, err := r.value(ctype)
		if err != nil {
			return nil, fmt.Errorf("field %d: %w", fieldID, err)
		}
		result[fieldID] = value
		previous = fieldID
	}
}

func (r *reader) value(ctype byte) (any, error) {
	switch ctype {
	case compactTrue:
		return true, nil
	case compactFalse:
		return false, nil
	case compactByte:
		value, err := r.byte()
		return int8(value), err
	case compactI16, compactI32, compactI64:
		return r.signed()
	case compactDouble:
		raw, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(raw)), nil
	case compactBinary:
		raw, err := r.binary()
		if err != nil {
			return nil, err
		}
		if utf8.Valid(raw) {
			return string(raw), nil
		}
		return append([]byte(nil), raw...), nil
	case compactList, compactSet:
		header, err := r.byte()
		if err != nil {
			return nil, err
		}
		size, elementType := int(header>>4), header&0x0f
		if size == 15 {
			longSize, err := r.varint()
			if err != nil {
				return nil, err
			}
			size = int(longSize)
		}
		values := make([]any, 0, size)
		for range size {
			value, err := r.value(elementType)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	case compactMap:
		size, err := r.varint()
		if err != nil {
			return nil, err
		}
		values := make(map[any]any, size)
		if size == 0 {
			return values, nil
		}
		types, err := r.byte()
		if err != nil {
			return nil, err
		}
		for range size {
			key, err := r.value(types >> 4)
			if err != nil {
				return nil, err
			}
			value, err := r.value(types & 0x0f)
			if err != nil {
				return nil, err
			}
			values[key] = value
		}
		return values, nil
	case compactStruct:
		return r.structValue()
	default:
		return nil, fmt.Errorf("unknown compact thrift type %d", ctype)
	}
}
