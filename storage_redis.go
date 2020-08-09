package main

import (
	"context"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/acme/autocert"
)

func NewRedisCache(redisURL string) (autocert.Cache, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	cache := &rediscache{}
	cache.client = redis.NewClient(opt)
	return cache, nil
}

type rediscache struct {
	client *redis.Client
}

func (c *rediscache) Get(ctx context.Context, key string) ([]byte, error) {
	return c.client.Get(key).Bytes()
}

func (c *rediscache) Put(ctx context.Context, key string, data []byte) error {
	return c.client.Set(key, data, 0).Err()
}

func (c *rediscache) Delete(ctx context.Context, key string) error {
	return c.client.Del(key).Err()
}
