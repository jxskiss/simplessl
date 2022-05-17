package server

import (
	"context"

	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/acme/autocert"
)

func NewRedisCache(cfg redisConfig) (autocert.Cache, error) {
	opt, err := redis.ParseURL(cfg.Addr)
	if err != nil {
		return nil, err
	}
	cache := &redisCache{
		prefix: cfg.Prefix,
	}
	cache.client = redis.NewClient(opt)
	return cache, nil
}

type redisCache struct {
	client *redis.Client
	prefix string
}

func (c *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	key = c.addPrefix(key)
	return c.client.Get(ctx, key).Bytes()
}

func (c *redisCache) Put(ctx context.Context, key string, data []byte) error {
	key = c.addPrefix(key)
	return c.client.Set(ctx, key, data, 0).Err()
}

func (c *redisCache) Delete(ctx context.Context, key string) error {
	key = c.addPrefix(key)
	return c.client.Del(ctx, key).Err()
}

func (c *redisCache) addPrefix(key string) string {
	return c.prefix + key
}
