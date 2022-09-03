package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

type HTTPAndTLSALPNSolver interface {
	acmez.Solver

	HandleACMEChallenge(w http.ResponseWriter, r *http.Request)
	GetALPNCertificate(token string) (*tls.Certificate, error)
}

func NewHTTPAndTLSALPNSolver() HTTPAndTLSALPNSolver {
	return &httpAndTLSALPNSolverImpl{
		byTokenChallenges:  make(map[string]*acme.Challenge),
		byDomainChallenges: make(map[string]*acme.Challenge),
		log:                zlog.Named("httpAndTLSALPNSolver"),
	}
}

type httpAndTLSALPNSolverImpl struct {
	chalMu             sync.RWMutex
	byTokenChallenges  map[string]*acme.Challenge // key: token
	byDomainChallenges map[string]*acme.Challenge // key: domain

	log *zap.Logger
}

func (p *httpAndTLSALPNSolverImpl) Present(_ context.Context, chal acme.Challenge) error {
	p.chalMu.Lock()
	defer p.chalMu.Unlock()
	p.byTokenChallenges[chal.Token] = &chal
	p.byDomainChallenges[chal.Identifier.Value] = &chal
	return nil
}

func (p *httpAndTLSALPNSolverImpl) CleanUp(_ context.Context, chal acme.Challenge) error {
	p.chalMu.Lock()
	defer p.chalMu.Unlock()
	if x := p.byTokenChallenges[chal.Token]; x != nil && x.KeyAuthorization == chal.KeyAuthorization {
		delete(p.byTokenChallenges, chal.Token)
	}
	if x := p.byDomainChallenges[chal.Identifier.Value]; x != nil && x.KeyAuthorization == chal.KeyAuthorization {
		delete(p.byDomainChallenges, chal.Identifier.Value)
	}
	return nil
}

func (p *httpAndTLSALPNSolverImpl) getChallenge(token string) *acme.Challenge {
	p.chalMu.Lock()
	defer p.chalMu.Unlock()
	return p.byTokenChallenges[token]
}

func (p *httpAndTLSALPNSolverImpl) HandleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	token := strings.TrimPrefix(r.URL.Path, prefix)

	var chal *acme.Challenge
	p.chalMu.RLock()
	chal = p.byTokenChallenges[token]
	p.chalMu.RUnlock()
	if chal == nil {
		p.log.With(zap.String("token", token)).Info("challenge not found")
		http.NotFound(w, r)
		return
	}

	w.Write([]byte(chal.KeyAuthorization))
	p.log.With(
		zap.String("domain", chal.Identifier.Value),
		zap.String("token", token)).
		Info("success served acme http-01 challenge")
}

func (p *httpAndTLSALPNSolverImpl) GetALPNCertificate(domain string) (*tls.Certificate, error) {
	var chal *acme.Challenge
	p.chalMu.RLock()
	chal = p.byDomainChallenges[domain]
	p.chalMu.RUnlock()
	if chal == nil {
		return nil, errors.New("challenge not found")
	}
	alpnCert, err := acmez.TLSALPN01ChallengeCert(*chal)
	if err != nil {
		return nil, err
	}

	p.log.With(zap.String("domain", domain)).Info("success served tls-alpn-01 certificate")
	return alpnCert, nil
}
