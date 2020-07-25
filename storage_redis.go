// +build redis

package main

import (
	"context"
	"flag"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/acme/autocert"
)

func init() {
	flag.StringVar(&store.redisDSN,
		"redis",
		"",
		"use redis as certificates cache storage (eg. 127.0.0.1:6379/0)")
	store.impl["redis"] = NewRedisCache
}

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
