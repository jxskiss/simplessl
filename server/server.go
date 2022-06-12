package server

type Server struct {
	AutocertMgr *Manager
	ManagedMgr  *ManagedCertManager
	OCSPManager *OCSPManager
}

func NewServer() *Server {
	ocspMgr := NewOCSPManager()
	managed := NewManagedCertManager(ocspMgr)
	manager := NewManager(managed, ocspMgr)
	return &Server{
		AutocertMgr: manager,
		ManagedMgr:  managed,
		OCSPManager: ocspMgr,
	}
}
