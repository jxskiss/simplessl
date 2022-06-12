package server

import (
	"context"
	"crypto/tls"

	"golang.org/x/crypto/acme/autocert"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

const (
	StorageTypeDirCache = "dir_cache"
	StorageTypeRedis    = "redis"
)

func NewDirCache(cacheDir string) (autocert.Cache, error) {
	return autocert.DirCache(cacheDir), nil
}

func NewStorageManager(cfg *Config) *StorageManager {
	return &StorageManager{
		cfg: cfg,
	}
}

type StorageManager struct {
	cfg *Config
}

// LoadCertificateFromStore loads certificate from storage, if the certificate
// exists and is valid, it will be returned, or an error otherwise.
func (p *StorageManager) LoadCertificateFromStore(certKey string) (tlscert *tls.Certificate, keyPEM, certPEM []byte, err error) {
	ctx := context.Background()
	data, err := p.cfg.Storage.Cache.Get(ctx, certKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return utils.ParseCertificate(data)
}

// SaveCertificateToStore saves certificate to storage.
func (p *StorageManager) SaveCertificateToStore(certKey string, privPEM, pubPEM []byte) error {
	ctx := context.Background()
	certBytes := utils.ConcatPrivAndPubKey(privPEM, pubPEM)
	err := p.cfg.Storage.Cache.Put(ctx, certKey, certBytes)
	if err != nil {
		return err
	}
	return nil
}
