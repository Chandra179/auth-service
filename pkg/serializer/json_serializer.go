package serializer

import (
	"bytes"
	"encoding/gob"
)

// JSONSerializer is an interface for objects that can serialize and deserialize data
type JSONSerializer interface {
	Encode(v interface{}) ([]byte, error)
	Decode(data []byte, v interface{}) error
}

// GobSerialization implements Serializer using Gob encoding
type GobSerialization struct{}

// NewGobSerialization creates a new GobSerializer with the specified Serializer
func NewGobSerialization() *GobSerialization {
	return &GobSerialization{}
}

func (gs *GobSerialization) Encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (gs *GobSerialization) Decode(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(v)
}
