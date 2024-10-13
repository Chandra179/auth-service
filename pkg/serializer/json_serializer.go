/*
Package serializer provides utilities for serializing and deserializing data.
Currently, it implements Gob serialization, but it is designed for easy extension to support other serialization formats in the future.

Components:
- JSONSerializer interface: Defines methods for encoding and decoding data.
- GobSerialization struct: Implements the JSONSerializer interface using Gob encoding.

Usage:
To use this package, create an instance of GobSerialization, then call the Encode and Decode methods
to serialize and deserialize data respectively.
*/

// Package serializer provides utilities for serializing and deserializing data.
package serializer

import (
	"bytes"        // For handling byte buffers
	"encoding/gob" // For Gob encoding and decoding
)

// JSONSerializer is an interface for objects that can serialize and deserialize data.
// It provides methods for encoding and decoding data structures.
type JSONSerializer interface {
	// Encode serializes the provided value into a byte slice.
	// Parameters:
	//   - v: The value to serialize.
	// Returns:
	//   - A byte slice containing the serialized data.
	//   - An error if the operation fails.
	Encode(v interface{}) ([]byte, error)

	// Decode deserializes data from a byte slice into the provided value.
	// Parameters:
	//   - data: The byte slice containing serialized data.
	//   - v: The value to populate with the deserialized data.
	// Returns:
	//   - An error if the operation fails.
	Decode(data []byte, v interface{}) error
}

// GobSerialization implements JSONSerializer using Gob encoding.
type GobSerialization struct{}

// NewGobSerialization creates a new instance of GobSerialization.
// Returns:
//   - A pointer to the newly created GobSerialization instance.
func NewGobSerialization() *GobSerialization {
	return &GobSerialization{}
}

// Encode serializes the provided value using Gob encoding.
// Parameters:
//   - v: The value to serialize.
//
// Returns:
//   - A byte slice containing the serialized data.
//   - An error if the encoding operation fails.
func (gs *GobSerialization) Encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf) // Create a new Gob encoder
	err := enc.Encode(v)        // Encode the value into the buffer
	if err != nil {
		return nil, err // Return nil and the error if encoding fails
	}
	return buf.Bytes(), nil // Return the serialized data as a byte slice
}

// Decode deserializes data from a byte slice into the provided value using Gob decoding.
// Parameters:
//   - data: The byte slice containing serialized data.
//   - v: The value to populate with the deserialized data.
//
// Returns:
//   - An error if the decoding operation fails.
func (gs *GobSerialization) Decode(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data) // Create a new buffer from the byte slice
	dec := gob.NewDecoder(buf)   // Create a new Gob decoder
	return dec.Decode(v)         // Decode the data into the provided value
}
