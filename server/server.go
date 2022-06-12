package server

import (
	"context"

	"github.com/jxskiss/ssl-cert-server/pkg/lego"
)

type Opts struct {
	ConfigFile string `cli:"-c, --config, configuration filename" default:"./conf.yaml"`
}

type Server struct {
	Cfg         *Config
	AutocertMgr *Manager
	ManagedMgr  *ManagedCertManager
	WildcardMgr *WildcardManager
	OCSPManager *OCSPManager
}

func NewServer(cfg *Config) (*Server, error) {
	ocspMgr := NewOCSPManager()

	svr := &Server{
		Cfg:         cfg,
		AutocertMgr: nil,
		ManagedMgr:  nil,
		WildcardMgr: nil,
		OCSPManager: ocspMgr,
	}

	managed := NewManagedCertManager(svr)
	svr.ManagedMgr = managed

	autocertMgr := NewManager(svr)
	svr.AutocertMgr = autocertMgr

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
		wildcardMgr := NewWildcardManager(svr, legoApp)
		svr.WildcardMgr = wildcardMgr
	}

	return svr, nil
}
