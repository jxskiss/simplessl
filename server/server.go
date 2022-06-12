package server

type Opts struct {
	ConfigFile string `cli:"-c, --config, configuration filename" default:"./conf.yaml"`
}

type Server struct {
	AutocertMgr *Manager
	ManagedMgr  *ManagedCertManager
	OCSPManager *OCSPManager
}

func NewServer() *Server {
	ocspMgr := NewOCSPManager()
	managed := NewManagedCertManager(ocspMgr)
	wildcard := NewWildcardManager(ocspMgr)
	manager := NewManager(wildcard, managed, ocspMgr)
	return &Server{
		AutocertMgr: manager,
		ManagedMgr:  managed,
		OCSPManager: ocspMgr,
	}
}
