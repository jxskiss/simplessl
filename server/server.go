package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
	"golang.org/x/net/idna"
	"storj.io/drpc/drpcerr"

	"github.com/jxskiss/ssl-cert-server/pkg/config"
	"github.com/jxskiss/ssl-cert-server/pkg/pb"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

type Server struct {
	pb.DRPCCertServerUnimplementedServer

	cfg        *config.Config
	selfSinged SelfSignedManager
	managed    ManagedCertManager
	acme       ACMEManager
	ocsp       OCSPManager
	httpSolver HTTPAndTLSALPNSolver

	log *zap.SugaredLogger
}

func NewServer(
	cfg *config.Config,
	selfSigned SelfSignedManager,
	managed ManagedCertManager,
	acme ACMEManager,
	ocsp OCSPManager,
	httpSolver HTTPAndTLSALPNSolver,
) *Server {
	return &Server{
		cfg:        cfg,
		selfSinged: selfSigned,
		managed:    managed,
		acme:       acme,
		ocsp:       ocsp,
		httpSolver: httpSolver,
		log:        zlog.Named("server").Sugar(),
	}
}

func (p *Server) GetCertificate(ctx context.Context, req *pb.GetCertificateRequest) (*pb.GetCertificateResponse, error) {
	var err error
	var certName string
	var certTyp pb.Certificate_Type
	var cert *tls.Certificate
	var disableOCSPStapling bool
	if req.IsAlpn {
		certName = req.GetDomain()
		certTyp = pb.Certificate_ALPN
		cert, err = p.httpSolver.GetALPNCertificate(certName)
	} else {
		if req.GetDomain() != "" {
			domain := req.GetDomain()
			domain, err := idna.Lookup.ToASCII(domain)
			if err != nil {
				p.log.With(zap.Error(err)).Infof("got invalid domain name, domain= %v", domain)
				return nil, ErrInvalidDomainName
			}
			certTyp, certName = p.cfg.CheckCertTypeByDomain(domain)
		} else if req.GetName() != "" {
			certTyp, certName = p.cfg.CheckCertTypeByName(req.GetName())
		}

		switch certTyp {
		case pb.Certificate_UNKNOWN:
			return nil, ErrHostNotPermitted
		case pb.Certificate_SELF_SIGNED:
			cert, err = p.selfSinged.GetCertificate(ctx)
		case pb.Certificate_MANAGED:
			disableOCSPStapling = !p.cfg.IsManagedCertEnableOCSPStapling(certName)
			cert, err = p.managed.GetCertificate(ctx, certName)
		case pb.Certificate_ACME_NAMED:
			cert, err = p.acme.GetNamedCertificate(ctx, certName, true)
		case pb.Certificate_ACME_ON_DEMAND:
			cert, err = p.acme.GetOnDemandCertificate(ctx, certName, true)
		}
	}
	if err != nil {
		p.log.With(zap.Error(err)).Errorf("failed get certificate, typ= %v, name= %v", certTyp, certName)
		return nil, ErrGetCertificate
	}
	if time.Until(cert.Leaf.NotAfter) <= 0 {
		p.log.Warnf("got expired certificate, typ= %v, name= %v", certTyp, certName)
		return nil, ErrCertificateIsExpired
	}

	pbCert, err := marshalCertToPb(certTyp, cert, disableOCSPStapling)
	if err != nil {
		p.log.With(zap.Error(err)).Errorf("failed marshal certificate, typ= %v, name= %v", certTyp, certName)
		return nil, ErrMarshalCertificate
	}
	resp := &pb.GetCertificateResponse{
		Cert:         pbCert,
		OcspStapling: nil,
	}
	return resp, nil
}

func (p *Server) GetOCSPStapling(ctx context.Context, req *pb.GetOCSPStaplingRequest) (*pb.GetOCSPStaplingResponse, error) {
	domain := req.GetDomain()
	fp := req.GetFingerprint()
	domain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		p.log.With(zap.Error(err)).Infof("got invalid domain name, domain= %v", domain)
		return nil, drpcerr.WithCode(ErrInvalidDomainName, CodeBadRequest)
	}

	certTyp, certName := p.cfg.CheckCertTypeByDomain(domain)
	switch certTyp {
	case pb.Certificate_UNKNOWN:
		return nil, drpcerr.WithCode(ErrHostNotPermitted, CodeBadRequest)
	case pb.Certificate_ALPN,
		pb.Certificate_SELF_SIGNED:
		return nil, drpcerr.WithCode(ErrOCSPStaplingNotSupported, CodeBadRequest)
	}

	ocspKey := getOCSPKey(certTyp, certName)
	checkCachedCert := func() (*tls.Certificate, error) {
		switch certTyp {
		case pb.Certificate_MANAGED:
			return p.managed.GetCertificate(ctx, certName)
		case pb.Certificate_ACME_ON_DEMAND:
			return p.acme.GetOnDemandCertificate(ctx, certName, false)
		case pb.Certificate_ACME_NAMED:
			return p.acme.GetNamedCertificate(ctx, certName, false)
		}
		return nil, ErrHostNotPermitted
	}
	ocspStapling, nextUpdate, err := p.ocsp.GetOCSPStapling(ctx, ocspKey, fp, checkCachedCert)
	if err != nil {
		p.log.With(zap.Error(err)).Errorf("failed get OCSP stapling, domain= %v, fp= %v", domain, fp)
		return nil, err
	}

	var ttl int64
	if !nextUpdate.IsZero() {
		ttl = utils.LimitTTL(time.Until(nextUpdate))
	}
	resp := &pb.GetOCSPStaplingResponse{
		OcspStapling: &pb.OCSPStapling{
			Raw:           ocspStapling,
			NextUpdateSec: nextUpdate.Unix(),
			TtlSec:        ttl,
		},
	}
	return resp, nil
}

func marshalCertToPb(typ pb.Certificate_Type, cert *tls.Certificate, disableOCSPStapling bool) (*pb.Certificate, error) {
	var (
		err        error
		certBuf    bytes.Buffer
		privKeyBuf bytes.Buffer
	)
	for _, b := range cert.Certificate {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err = pem.Encode(&certBuf, block); err != nil {
			return nil, fmt.Errorf("encode certificate: %w", err)
		}
	}
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = utils.EncodeRSAKey(&privKeyBuf, key)
	case *ecdsa.PrivateKey:
		err = utils.EncodeECDSAKey(&privKeyBuf, key)
	default:
		err = fmt.Errorf("unknown private key type")
	}
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}

	// Leaf and fingerprint are not needed for tls-alpn-01 certificate.
	var fingerprint string
	if cert.Leaf != nil {
		fingerprint = utils.CalcCertFingerprint(cert.Leaf)
	}

	ttl := utils.LimitTTL(time.Until(cert.Leaf.NotAfter))
	hasOCSPStapling := false
	if cert.Leaf != nil && len(cert.Leaf.OCSPServer) > 0 && !disableOCSPStapling {
		switch typ {
		case pb.Certificate_MANAGED,
			pb.Certificate_ACME_ON_DEMAND,
			pb.Certificate_ACME_NAMED:
			hasOCSPStapling = true
		}
	}

	pbCert := &pb.Certificate{
		Type:            int32(typ),
		PubKey:          string(certBuf.Bytes()),
		PrivKey:         string(privKeyBuf.Bytes()),
		Fp:              fingerprint,
		NotBeforeSec:    cert.Leaf.NotBefore.Unix(),
		NotAfterSec:     cert.Leaf.NotAfter.Unix(),
		TtlSec:          ttl,
		HasOcspStapling: hasOCSPStapling,
	}
	return pbCert, nil
}
