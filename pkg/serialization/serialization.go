package serialization

import (
	"bytes"
	"encoding/gob"
)

// Serializer is an interface for objects that can serialize and deserialize data
type Serializer interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}

// GobSerializer implements Serializer using Gob encoding
type GobSerializer struct{}

func (gs *GobSerializer) Marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (gs *GobSerializer) Unmarshal(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(v)
}

// SerializationManager handles serialization and deserialization
type SerializationManager struct {
	serializer Serializer
}

// NewSerializationManager creates a new SerializationManager with the specified Serializer
func NewSerializationManager(serializer Serializer) *SerializationManager {
	return &SerializationManager{serializer: serializer}
}

// ToBytes converts a struct to bytes
func (sm *SerializationManager) ToBytes(v interface{}) ([]byte, error) {
	return sm.serializer.Marshal(v)
}

// FromBytes converts bytes to a struct
func (sm *SerializationManager) FromBytes(data []byte, v interface{}) error {
	return sm.serializer.Unmarshal(data, v)
}
