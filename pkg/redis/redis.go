/*
Package redis provides a simple abstraction over the Redis client for common operations
such as setting, getting, and deleting key-value pairs. This package allows for easy integration
with Redis and can be used to cache data or store session information.

Components:
- RedisStore interface: Defines the methods for interacting with Redis.
- RedisClient struct: Implements the RedisStore interface and wraps the Redis client for common operations.

Usage:
To use this package, create a Redis client using the NewRedisClient function, then call the
Set, Get, and Delete methods to manipulate key-value pairs in the Redis store.
*/

// Package redis provides an abstraction over Redis client operations.
package redis

import (
	"context"
	"log"
	"time"

	"github.com/redis/go-redis/v9" // Importing the Redis Go client
)

// RedisStore defines an interface for interacting with Redis.
// It provides methods to set, get, and delete key-value pairs.
type RedisStore interface {
	// Set a key-value pair in Redis with an optional expiration time.
	// Parameters:
	//   - key: The key under which to store the value.
	//   - value: The value to store.
	//   - expiration: The time duration after which the key will expire.
	// Returns:
	//   - An error if the operation fails.
	Set(key string, value interface{}, expiration time.Duration) error

	// Get retrieves the value associated with a given key.
	// Parameters:
	//   - key: The key for which to retrieve the value.
	// Returns:
	//   - The value as a byte slice and an error if the operation fails.
	Get(key string) ([]byte, error)

	// Delete removes a key from Redis.
	// Parameters:
	//   - key: The key to delete.
	// Returns:
	//   - An error if the operation fails.
	Delete(key string) error
}

// RedisClient wraps the redis.Client to expose common operations.
type RedisClient struct {
	client *redis.Client   // The Redis client
	ctx    context.Context // The context for operations
}

// NewRedisClient creates a new Redis client abstraction.
// It establishes a connection to the Redis server and verifies the connection by sending a PING.
// Parameters:
//   - addr: The address of the Redis server.
//   - password: The password for the Redis server (if any).
//   - db: The database number to connect to.
//
// Returns:
//   - A pointer to the RedisClient instance.
func NewRedisClient(addr string, password string, db int) *RedisClient {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Testing connection
	ctx := context.Background()
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	return &RedisClient{
		client: rdb,
		ctx:    ctx,
	}
}

// Set a key-value pair in Redis with an optional expiration time.
// Parameters:
//   - key: The key under which to store the value.
//   - value: The value to store.
//   - expiration: The time duration after which the key will expire.
//
// Returns:
//   - An error if the operation fails.
func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(r.ctx, key, value, expiration).Err()
}

// Get retrieves the value for a given key.
// Parameters:
//   - key: The key for which to retrieve the value.
//
// Returns:
//   - The value as a byte slice and an error if the operation fails.
func (r *RedisClient) Get(key string) ([]byte, error) {
	return r.client.Get(r.ctx, key).Bytes()
}

// Delete removes a key from Redis.
// Parameters:
//   - key: The key to delete.
//
// Returns:
//   - An error if the operation fails.
func (r *RedisClient) Delete(key string) error {
	return r.client.Del(r.ctx, key).Err()
}
