package redis

import (
	"context"
	"time"

	"log"

	"github.com/redis/go-redis/v9"
)

type RedisStore interface {
	Set(key string, value interface{}, expiration time.Duration) error
	Get(key string) ([]byte, error)
	Delete(key string) error
}

// RedisClient wraps the redis.Client to expose common operations.
type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisClient creates a new Redis client abstraction.
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
func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(r.ctx, key, value, expiration).Err()
}

// Get retrieves the value for a given key.
func (r *RedisClient) Get(key string) ([]byte, error) {
	return r.client.Get(r.ctx, key).Bytes()
}

// Delete removes a key from Redis.
func (r *RedisClient) Delete(key string) error {
	return r.client.Del(r.ctx, key).Err()
}
