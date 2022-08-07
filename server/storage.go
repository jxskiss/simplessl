package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

const (
	StorageTypeDirCache = "dir_cache"
	StorageTypeRedis    = "redis"
)

var ErrCacheMiss = errors.New("cache miss")

type Storage interface {
	Get(ctx context.Context, key string) (data []byte, err error)
	Put(ctx context.Context, key string, data []byte) error
	Delete(ctx context.Context, key string) error
}

func NewDirCache(dir string) Storage {
	return &dirCacheImpl{dir: dir}
}

type dirCacheImpl struct {
	dir string
}

func (p *dirCacheImpl) Get(ctx context.Context, key string) (data []byte, err error) {
	name := filepath.Join(p.dir, key)
	done := make(chan struct{})
	go func() {
		data, err = os.ReadFile(name)
		close(done)
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}
	if os.IsNotExist(err) {
		return nil, ErrCacheMiss
	}
	return data, err
}

func (p *dirCacheImpl) Put(ctx context.Context, key string, data []byte) error {
	if err := os.MkdirAll(p.dir, 0700); err != nil {
		return err
	}

	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		var tmp string
		if tmp, err = p.writeTempFile(key, data); err != nil {
			return
		}
		defer os.Remove(tmp)
		select {
		case <-ctx.Done():
			// Don't overwrite the file if the context was canceled.
		default:
			newName := filepath.Join(p.dir, key)
			err = os.Rename(tmp, newName)
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	return err
}

func (p *dirCacheImpl) Delete(ctx context.Context, key string) (err error) {
	name := filepath.Join(p.dir, key)
	done := make(chan struct{})
	go func() {
		err = os.Remove(name)
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (p *dirCacheImpl) writeTempFile(prefix string, data []byte) (name string, reterr error) {
	tmpDir := filepath.Join(p.dir, ".temp")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return "", err
	}

	// Temp file uses 0600 permissions.
	f, err := os.CreateTemp(tmpDir, prefix)
	if err != nil {
		return "", err
	}
	defer func() {
		if reterr != nil {
			os.Remove(f.Name())
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}
