package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jxskiss/gopkg/v2/perf/json"
	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
	"storj.io/drpc/drpcerr"
	"storj.io/drpc/drpchttp"
	"storj.io/drpc/drpcmux"

	"github.com/jxskiss/ssl-cert-server/pkg/pb"
)

const (
	acmeChallengePath  = "/.well-known/acme-challenge/"
	v1CertificatePath  = "/cert/"
	v1OCSPStaplingPath = "/ocsp/"
)

func NewMux(server *Server) (*Mux, error) {
	httpAPI := NewV1API(server)
	drpcM := drpcmux.New()
	err := pb.DRPCRegisterCertServer(drpcM, server)
	if err != nil {
		return nil, err
	}
	mux := &Mux{
		v1API:       httpAPI,
		drpcHandler: drpchttp.New(drpcM),
	}
	return mux, nil
}

type Mux struct {
	v1API       V1API
	drpcHandler http.Handler
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handleFunc := m.v1API.GetHandler(r); handleFunc != nil {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handleFunc(w, r)
	} else {
		m.drpcHandler.ServeHTTP(w, r)
	}
}

type V1API interface {
	GetHandler(r *http.Request) http.HandlerFunc
}

func NewV1API(server *Server) V1API {
	return &v1APIImpl{
		server: server,
		log:    zlog.Named("v1api").Sugar(),
	}
}

type v1APIImpl struct {
	server *Server

	log *zap.SugaredLogger
}

func (p *v1APIImpl) GetHandler(r *http.Request) http.HandlerFunc {
	path := r.URL.Path
	if strings.HasPrefix(path, v1CertificatePath) {
		return p.HandleCertificate
	}
	if strings.HasPrefix(path, v1OCSPStaplingPath) {
		return p.HandleOCSPStapling
	}
	if strings.HasPrefix(path, acmeChallengePath) {
		return p.HandleACMEChallenge
	}
	return nil
}

// HandleACMEChallenge handles requests of ACME challenges.
func (p *v1APIImpl) HandleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	p.server.httpSolver.HandleACMEChallenge(w, r)
}

// HandleCertificate handles legacy requests of SSL certificate.
//
// Possible responses are:
// - 200 with the certificate data as response
// - 400 the requested domain name is invalid or not permitted
// - 500 which indicates the server failed to process the request,
//       in such case, the body will be filled with the error message
func (p *v1APIImpl) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domain := strings.TrimPrefix(r.URL.Path, "/cert/")
	isALPN01 := r.URL.Query().Get("alpn") == "1"
	req := &pb.GetCertificateRequest{
		Domain:           domain,
		IsAlpn:           isALPN01,
		WantOcspStapling: false,
	}
	resp, err := p.server.GetCertificate(ctx, req)
	if err != nil {
		code := drpcerr.Code(err)
		switch {
		case code == CodeBadRequest:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
		return
	}

	cert := resp.GetCert()
	certTyp := convertToV1CertType(pb.Certificate_Type(cert.Type))
	v1Resp := &v1CertificateResponse{
		Type:        certTyp,
		Cert:        cert.PubKey,
		PKey:        cert.PrivKey,
		Fingerprint: cert.Fp,
		ExpireAt:    cert.NotAfterSec,
		TTL:         cert.TtlSec,
	}
	v1Resp.write(w)
}

// HandleOCSPStapling handles legacy requests of OCSP stapling.
//
// Possible responses are:
// - 200 with the OCSP response as body
// - 204 without body, which indicates OCSP stapling for the requested domain
//       is not available, temporarily or permanently
// - 400 which indicates the requested domain name is invalid or not permitted
func (p *v1APIImpl) HandleOCSPStapling(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/ocsp/")
	fingerprint := r.URL.Query().Get("fp")

	ctx := r.Context()
	req := &pb.GetOCSPStaplingRequest{
		Domain:      domain,
		Fingerprint: fingerprint,
	}
	resp, err := p.server.GetOCSPStapling(ctx, req)
	if err != nil {
		code := drpcerr.Code(err)
		switch {
		case code == CodeBadRequest:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		default:
			w.WriteHeader(http.StatusNoContent)
			w.Write([]byte(err.Error()))
		}
		return
	}

	stapling := resp.GetOcspStapling()
	if stapling == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	v1Resp := &v1OCSPStaplingResponse{
		Raw:      stapling.Raw,
		ExpireAt: stapling.NextUpdateSec,
		TTL:      stapling.TtlSec,
	}
	v1Resp.write(w)
}

// V1 certificate types.
//
// - smaller than 100 for certificates which have OCSP stapling;
// - equal or larger than 100 for certificates which don't have OCSP stapling;
const (
	v1TypeLetsEncrypt = 0
	v1TypeManaged     = 1
	v1TypeWildcard    = 2
	v1TypeSelfSigned  = 100
	v1TypeALPNCert    = 101
)

func convertToV1CertType(typ pb.Certificate_Type) int {
	switch typ {
	case pb.Certificate_ALPN:
		return v1TypeALPNCert
	case pb.Certificate_SELF_SIGNED:
		return v1TypeSelfSigned
	case pb.Certificate_MANAGED:
		return v1TypeManaged
	case pb.Certificate_ACME_ON_DEMAND:
		return v1TypeLetsEncrypt
	case pb.Certificate_ACME_NAMED:
		return v1TypeWildcard
	}
	return 0
}

type v1CertificateResponse struct {
	Type        int    `json:"type"`
	Cert        string `json:"cert"`
	PKey        string `json:"pkey"`
	Fingerprint string `json:"fingerprint"`
	ExpireAt    int64  `json:"expire_at"` // seconds since epoch
	TTL         int64  `json:"ttl"`       // in seconds
}

func (p *v1CertificateResponse) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := json.Marshal(p)
	w.Write(body)
}

type v1OCSPStaplingResponse struct {
	Raw      []byte
	ExpireAt int64 // seconds since epoch
	TTL      int64 // in seconds
}

func (p *v1OCSPStaplingResponse) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("X-Expire-At", fmt.Sprintf("%d", p.ExpireAt))
	w.Header().Set("X-TTL", fmt.Sprintf("%d", p.TTL))
	w.Write(p.Raw)
}
