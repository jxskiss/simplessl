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

	"github.com/jxskiss/simplessl/pkg/config"
	"github.com/jxskiss/simplessl/pkg/pb"
	"github.com/jxskiss/simplessl/pkg/utils"
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
	resp, _, err := p.internalGetCertificate(ctx, req)
	return resp, err
}

func (p *Server) SDSCertProvider(ctx context.Context, req *pb.GetCertificateRequest) (
	resp *pb.GetCertificateResponse, certKey string, err error) {
	return p.internalGetCertificate(ctx, req)
}

func (p *Server) internalGetCertificate(ctx context.Context, req *pb.GetCertificateRequest) (
	resp *pb.GetCertificateResponse, certKey string, err error) {

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
				p.log.Infof("got invalid domain name, domain= %v", domain)
				return nil, "", drpcerr.WithCode(ErrInvalidDomainName, CodeBadRequest)
			}
			certTyp, certName = p.cfg.CheckCertTypeByDomain(domain)
		} else if req.GetName() != "" {
			certTyp, certName = p.cfg.CheckCertTypeByName(req.GetName())
		} else {
			p.log.Infof("got invalid request, no doman and certName")
			return nil, "", drpcerr.WithCode(ErrInvalidRequestData, CodeBadRequest)
		}

		switch certTyp {
		case pb.Certificate_UNKNOWN:
			p.log.Infof("cannot determine certificate type, certName= %v", certName)
			return nil, "", drpcerr.WithCode(ErrHostNotPermitted, CodeBadRequest)
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
		return nil, "", drpcerr.WithCode(ErrGetCertificate, CodeInternalError)
	}
	if time.Until(cert.Leaf.NotAfter) <= 0 {
		p.log.Errorf("got expired certificate, typ= %v, name= %v", certTyp, certName)
		return nil, "", drpcerr.WithCode(ErrCertificateIsExpired, CodeInternalError)
	}

	pbCert, err := marshalCertToPb(certTyp, cert, disableOCSPStapling)
	if err != nil {
		p.log.With(zap.Error(err)).Errorf("failed marshal certificate, typ= %v, name= %v", certTyp, certName)
		return nil, "", drpcerr.WithCode(ErrMarshalCertificate, CodeInternalError)
	}

	var ocspStapling *pb.OCSPStapling
	if req.GetWantOcspStapling() && pbCert.HasOcspStapling {
		ocspResp, _ := p.getOCSPStaplingByCertTypeAndName(ctx, certTyp, certName, pbCert.Fp)
		ocspStapling = ocspResp.GetOcspStapling()
	}

	p.log.Infof("success get certificate, typ= %v, name= %v", certTyp, certName)
	resp = &pb.GetCertificateResponse{
		Cert:         pbCert,
		OcspStapling: ocspStapling,
	}
	certKey = getCertKey(certTyp, certName)
	return resp, certKey, nil
}

func (p *Server) GetOCSPStapling(ctx context.Context, req *pb.GetOCSPStaplingRequest) (*pb.GetOCSPStaplingResponse, error) {
	resp, domain, err := p.internalGetOCSPStapling(ctx, req)
	if err == nil {
		p.log.Infof("success get OCSP stapling, domain= %v, fp= %v", domain, req.GetFingerprint())
		return resp, nil
	}

	switch err {
	case ErrInvalidDomainName:
		p.log.Infof("got invalid domain name, domain= %v", domain)
		return nil, drpcerr.WithCode(ErrInvalidDomainName, CodeBadRequest)
	case ErrHostNotPermitted:
		p.log.Infof("host is not permitted, domain= %v", domain)
		return nil, drpcerr.WithCode(ErrHostNotPermitted, CodeBadRequest)
	case ErrOCSPStaplingNotSupported:
		p.log.Infof("OCSP stapling is not supported, domain= %v", domain)
		return nil, drpcerr.WithCode(ErrOCSPStaplingNotSupported, CodeBadRequest)
	case ErrOCSPStaplingNotCached:
		p.log.Infof("OCSP stapling is not cached, domain= %v", domain)
		return nil, drpcerr.WithCode(ErrOCSPStaplingNotCached, CodeNoContent)
	default:
		p.log.With(zap.Error(err)).Errorf("failed get OCSP stapling, domain= %v, fp= %v", domain, req.GetFingerprint())
		return nil, drpcerr.WithCode(err, CodeInternalError)
	}
}

func (p *Server) internalGetOCSPStapling(ctx context.Context, req *pb.GetOCSPStaplingRequest) (
	resp *pb.GetOCSPStaplingResponse, domain string, err error) {
	domain = req.GetDomain()
	fp := req.GetFingerprint()
	asciiDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		err = ErrInvalidDomainName
		return
	}
	domain = asciiDomain

	certTyp, certName := p.cfg.CheckCertTypeByDomain(domain)
	switch certTyp {
	case pb.Certificate_UNKNOWN:
		err = ErrHostNotPermitted
		return
	case pb.Certificate_ALPN, pb.Certificate_SELF_SIGNED:
		err = ErrOCSPStaplingNotSupported
		return
	}

	resp, err = p.getOCSPStaplingByCertTypeAndName(ctx, certTyp, certName, fp)
	return resp, domain, err
}

func (p *Server) getOCSPStaplingByCertTypeAndName(
	ctx context.Context, certTyp pb.Certificate_Type, certName string, fp string) (
	resp *pb.GetOCSPStaplingResponse, err error) {

	certKey := getCertKey(certTyp, certName)
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
	ocspStapling, nextUpdate, err := p.ocsp.GetOCSPStapling(ctx, certKey, fp, checkCachedCert)
	if err != nil {
		return
	}

	var ttl int64
	if !nextUpdate.IsZero() {
		ttl = utils.LimitTTL(time.Until(nextUpdate))
	}
	resp = &pb.GetOCSPStaplingResponse{
		OcspStapling: &pb.OCSPStapling{
			Raw:           ocspStapling,
			NextUpdateSec: nextUpdate.Unix(),
			TtlSec:        ttl,
		},
	}
	return
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
