package server

import (
	"context"

	"github.com/go-redis/redis/v8"

	"github.com/jxskiss/simplessl/pkg/config"
)

func NewRedisCache(cfg config.RedisConfig) (Storage, error) {
	opt, err := redis.ParseURL(cfg.Addr)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opt)
	impl := &redisCacheImpl{
		client: client,
		prefix: cfg.Prefix,
	}
	return impl, nil
}

type redisCacheImpl struct {
	client *redis.Client
	prefix string
}

func (c *redisCacheImpl) Get(ctx context.Context, key string) (data []byte, err error) {
	key = c.addPrefix(key)
	return c.client.Get(ctx, key).Bytes()
}

func (c *redisCacheImpl) Put(ctx context.Context, key string, data []byte) error {
	key = c.addPrefix(key)
	return c.client.Set(ctx, key, data, 0).Err()
}

func (c *redisCacheImpl) Delete(ctx context.Context, key string) error {
	key = c.addPrefix(key)
	return c.client.Del(ctx, key).Err()
}

func (c *redisCacheImpl) addPrefix(key string) string {
	return c.prefix + key
}
