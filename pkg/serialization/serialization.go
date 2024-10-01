package serialization

import (
	"bytes"
	"encoding/gob"
)

// SerializationOperations is an interface for objects that can serialize and deserialize data
type SerializationOperations interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}

// GobSerialization implements Serializer using Gob encoding
type GobSerialization struct{}

// NewGobSerialization creates a new GobSerializer with the specified Serializer
func NewGobSerialization() *GobSerialization {
	return &GobSerialization{}
}

func (gs *GobSerialization) Marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (gs *GobSerialization) Unmarshal(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(v)
}
