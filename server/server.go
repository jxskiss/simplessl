package server

import (
	"context"
	"crypto/tls"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"

	"github.com/jxskiss/ssl-cert-server/pkg/lego"
)

type Opts struct {
	ConfigFile string `cli:"-c, --config, configuration filename" default:"./conf.yaml"`
}

type Server struct {
	cfg      *Config
	stor     *StorageManager
	autocert *AutocertManager
	managed  *ManagedCertManager
	wildcard *WildcardManager
	ocspMgr  *OCSPManager

	log *zap.SugaredLogger
}

func NewServer(cfg *Config) (*Server, error) {
	ocspMgr := NewOCSPManager()
	storMgr := NewStorageManager(cfg)
	autocertMgr := NewAutocertManager(cfg, ocspMgr)
	managedMgr := NewManagedCertManager(storMgr, ocspMgr)

	server := &Server{
		cfg:      cfg,
		stor:     storMgr,
		autocert: autocertMgr,
		managed:  managedMgr,
		wildcard: nil,
		ocspMgr:  ocspMgr,
		log:      zlog.Named("server").Sugar(),
	}

	if len(cfg.Wildcard.Certificates) > 0 {
		ctx := context.Background()
		acmeAcc, privKey, err := autocertMgr.GetACMEAccount(ctx)
		if err != nil {
			return nil, err
		}
		legoAcc, err := lego.FromACMEAccount(cfg.LetsEncrypt.Email, acmeAcc, privKey)
		if err != nil {
			return nil, err
		}
		legoApp, err := lego.NewApp(cfg.Wildcard.LegoDataPath, cfg.LetsEncrypt.DirectoryURL, legoAcc)
		if err != nil {
			return nil, err
		}
		wildcardMgr := NewWildcardManager(cfg, storMgr, ocspMgr, legoApp)
		server.wildcard = wildcardMgr
	}

	return server, nil
}

func (p *Server) getCachedCertificateForOCSPStapling(name, fingerprint string) (
	cert *tls.Certificate,
	err error,
) {
	if IsSelfSignedCertificate(fingerprint) {
		return nil, ErrOCSPNotSupported
	}
	if ck, ok := p.cfg.IsManagedDomain(name); ok {
		return p.managed.Get(ck)
	}
	if wcItem, ok := p.cfg.IsWildcardDomain(name); ok {
		return p.wildcard.Get(wcItem, false)
	}

	// Else check cached certificates from Let's Encrypt, but don't trigger
	// requests to issue new certificates.
	err = p.cfg.LetsEncrypt.HostPolicy(context.Background(), name)
	if err != nil {
		return nil, err
	}
	return p.autocert.GetCachedCertificate(name)
}
