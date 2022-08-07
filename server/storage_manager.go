package server

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/jxskiss/ssl-cert-server/pkg/config"
	"github.com/jxskiss/ssl-cert-server/pkg/pb"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

const (
	accountPrivateKeyPrefix = "acc_privkey_"
)

type StorageManager interface {
	GetAccountPrivateKey(ctx context.Context, email string) ([]byte, error)
	SaveAccountPrivateKey(ctx context.Context, email string, data []byte) error
	LoadCertificate(ctx context.Context, certTyp pb.Certificate_Type, key string) (cert *tls.Certificate, pubKey, privKey []byte, err error)
	SaveCertificate(ctx context.Context, certTyp pb.Certificate_Type, key string, pubKey, privKey []byte) error
}

func NewStorageManager(cfg *config.Config, storage Storage) StorageManager {
	return &storageManagerImpl{
		cfg:  cfg,
		stor: storage,
	}
}

type storageManagerImpl struct {
	cfg  *config.Config
	stor Storage
}

func (p *storageManagerImpl) GetAccountPrivateKey(ctx context.Context, email string) ([]byte, error) {
	v2Key := accountPrivateKeyPrefix + email
	privKey, err := p.stor.Get(ctx, v2Key)
	if err == nil {
		return privKey, nil
	}

	// try load old account private key
	if err == ErrCacheMiss && email == p.cfg.ACME.DefaultAccount.Email {
		v1Key := "acme_account.key"
		privKey, err = p.stor.Get(ctx, v1Key)
	}
	return privKey, err
}

func (p *storageManagerImpl) SaveAccountPrivateKey(ctx context.Context, email string, data []byte) error {
	key := accountPrivateKeyPrefix + email
	return p.stor.Put(ctx, key, data)
}

func (p *storageManagerImpl) LoadCertificate(ctx context.Context, certTyp pb.Certificate_Type, key string) (cert *tls.Certificate, pubKey, privKey []byte, err error) {
	v2Key := fmt.Sprintf("%d_%s", certTyp, key)
	data, err := p.stor.Get(ctx, v2Key)
	if err != nil {
		if err == ErrCacheMiss {
			return p.tryLoadOldV1Certificate(ctx, certTyp, key)
		}
		return nil, nil, nil, err
	}
	return utils.ParseCertificate(data)
}

func (p *storageManagerImpl) tryLoadOldV1Certificate(ctx context.Context, certTyp pb.Certificate_Type, key string) (cert *tls.Certificate, pubKey, privKey []byte, err error) {
	switch certTyp {
	case pb.Certificate_SELF_SIGNED:
		key = "self_signed"
	case pb.Certificate_MANAGED:
		// pass
	case pb.Certificate_ACME_ON_DEMAND:
		if p.cfg.ACME.ForceRSA {
			key = key + "+rsa"
		}
	case pb.Certificate_ACME_NAMED:
		key = "wildcard_" + key
	}

	data, err := p.stor.Get(ctx, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return utils.ParseCertificate(data)
}

func (p *storageManagerImpl) SaveCertificate(ctx context.Context, certTyp pb.Certificate_Type, key string, pubKey, privKey []byte) error {
	key = fmt.Sprintf("%d_%s", certTyp, key)
	data := utils.ConcatPrivAndPubKey(privKey, pubKey)
	return p.stor.Put(ctx, key, data)
}
