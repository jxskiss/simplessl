package sds

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jxskiss/gopkg/v2/easy"
	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/montag451/go-eventbus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"

	"github.com/jxskiss/ssl-cert-server/pkg/bus"
	"github.com/jxskiss/ssl-cert-server/pkg/pb"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

// Identifier is the identifier of the secret discovery service.
var Identifier = "ssl-cert-server SDS/0000000-dev"

// ValidationContextName is the name used as a resource name for the validation context.
var ValidationContextName = "trusted_ca"

// ValidationContextAltName is an alternative name used as a resource name for
// the validation context.
var ValidationContextAltName = "validation_context"

// Service is the interface that an Envoy secret discovery service (SDS) has to
// implement. They serve TLS certificates to Envoy using gRPC.
//
//	type Service interface {
//		Register(s *grpc.Server)
//		discovery.SecretDiscoveryServiceServer
//	}
type Service struct {
	bus bus.EventBus
	cs  pb.DRPCCertServerServer

	logger *zap.Logger

	stopCh chan struct{}
}

// New creates a new sds.Service that will support multiple TLS certificates.
func New(bus bus.EventBus, cs pb.DRPCCertServerServer) *Service {
	logger := zlog.Named("sds")
	svc := &Service{
		bus:    bus,
		cs:     cs,
		stopCh: make(chan struct{}),
		logger: logger,
	}
	return svc
}

// Stop stops the current service.
func (srv *Service) Stop() error {
	close(srv.stopCh)
	return nil
}

// Register registers the sds.Service into the given gRPC server.
func (srv *Service) Register(s *grpc.Server) {
	secret.RegisterSecretDiscoveryServiceServer(s, srv)
}

func (srv *Service) DeltaSecrets(sds secret.SecretDiscoveryService_DeltaSecretsServer) (err error) {
	return status.Error(codes.Unimplemented, "method DeltaSecrets not implemented")
}

// StreamSecrets implements the gRPC SecretDiscoveryService service and returns
// a stream of TLS certificates.
func (srv *Service) StreamSecrets(sds secret.SecretDiscoveryService_StreamSecretsServer) (err error) {
	srv.logger.Info("serving StreamSecrets request")

	ctx := sds.Context()
	errCh := make(chan error)
	reqCh := make(chan *discovery.DiscoveryRequest)

	go func() {
		for {
			r, err := sds.Recv()
			if err != nil {
				errCh <- err
				return
			}
			reqCh <- r
		}
	}()

	var t1 time.Time
	var certTyp pb.Certificate_Type
	var certName string
	var tlsCert *tls.Certificate
	var changeCh chan string
	var nonce, versionInfo string
	var req *discovery.DiscoveryRequest
	var isRenewal bool

	for {
		select {
		case r := <-reqCh:
			t1 = time.Now()
			isRenewal = false

			// Validations
			if r.ErrorDetail != nil {
				srv.logRequest(ctx, r, "NACK", t1, nil)
				continue
			}
			// Do not validate nonce/version if we're restarting the server
			if req != nil {
				switch {
				case nonce != r.ResponseNonce:
					srv.logRequest(ctx, r, "Invalid responseNonce", t1, fmt.Errorf("invalid responseNonce"))
					continue
				case r.VersionInfo == "": // initial request
					versionInfo = srv.versionInfo()
				case r.VersionInfo == versionInfo: // ACK
					srv.logRequest(ctx, r, "ACK", t1, nil)
					continue
				default: // it should not go here
					versionInfo = srv.versionInfo()
				}
			} else {
				versionInfo = srv.versionInfo()
			}

			req = r

			if len(req.ResourceNames) > 1 {
				srv.logRequest(ctx, r, "multiple resourceNames not supported", t1, nil)
				return errors.New("multiple resourceNames not supported")
			}

			resourceName := req.ResourceNames[0]
			certTyp, certName, tlsCert, err = srv.getCertificate(ctx, resourceName)
			if err != nil {
				srv.logRequest(ctx, r, "error get certificate", t1, err)
				return err
			}

			changeCh = make(chan string)
			eventName := fmt.Sprintf("%d/%s", certTyp, certName)
			subHandler, err := srv.bus.SubscribeCertChangeEvent(eventName, func(e eventbus.Event, t time.Time) {
				changeCh <- resourceName
			})
			if err != nil {
				srv.logRequest(ctx, r, "error subscribe cert changes", t1, err)
				return err
			} else {
				msg := fmt.Sprintf("subscribed cert changes for %s", resourceName)
				srv.logRequest(ctx, r, msg, t1, nil)
				//nolint:gocritic
				defer srv.bus.Unsubscribe(subHandler)
			}
		case resourceName := <-changeCh:
			t1 = time.Now()
			isRenewal = true
			versionInfo = srv.versionInfo()
			certTyp, certName, tlsCert, err = srv.getCertificate(ctx, resourceName)
			if err != nil {
				srv.logRequest(ctx, req, "error renew certificate", t1, err)
				return err
			}
		case err := <-errCh:
			t1 = time.Now()
			if errors.Is(err, io.EOF) {
				return nil
			}
			srv.logRequest(ctx, nil, "Recv failed", t1, err)
			return err
		case <-srv.stopCh:
			return nil
		}

		// Send certificates
		dr, err := getDiscoveryResponse(req, versionInfo, []*tls.Certificate{tlsCert})
		if err != nil {
			srv.logRequest(ctx, req, "Creation of DiscoveryResponse failed", t1, err)
			return err
		}
		if err := sds.Send(dr); err != nil {
			srv.logRequest(ctx, req, "Send failed", t1, err)
			return err
		}

		nonce = dr.Nonce
		if isRenewal {
			srv.logRequest(ctx, req, "Certificate renewed", t1, err, zap.String("nonce", nonce))
		} else {
			srv.logRequest(ctx, req, "Certificate sent", t1, err, zap.String("nonce", nonce))
		}
	}
}

// FetchSecrets implements gRPC SecretDiscoveryService service and returns one TLS certificate.
func (srv *Service) FetchSecrets(ctx context.Context, r *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	ctx = srv.addRequestToContext(ctx, r)

	logger := zlog.GetSugaredLogger(ctx)
	logger.Debug("fetch request: %v", easy.JSON(r))

	if len(r.ResourceNames) > 1 {
		logger.Info("multiple resourceNames not supported")
		return nil, errors.New("multiple resourceNames not supported")
	}

	var err error
	var tlsCert *tls.Certificate
	var t1 = time.Now()
	resourceName := r.ResourceNames[0]
	_, _, tlsCert, err = srv.getCertificate(ctx, resourceName)
	if err != nil {
		srv.logRequest(ctx, r, "error get certificate", t1, err)
		return nil, err
	}

	versionInfo := time.Now().UTC().Format(time.RFC3339)
	return getDiscoveryResponse(r, versionInfo, []*tls.Certificate{tlsCert})
}

func (srv *Service) getCertificate(ctx context.Context, resourceName string) (
	certTyp pb.Certificate_Type, certName string, tlsCert *tls.Certificate, err error) {
	log := srv.logger.Sugar()
	log.Infof("getting certificate, resourceName= %v", resourceName)

	parts := strings.SplitN(resourceName, "/", 2)
	if len(parts) != 2 {
		log.Infof("got invalid resourceName: %v", resourceName)
		err = status.Error(codes.InvalidArgument, "resourceName is invalid")
		return 0, "", nil, err
	}

	var req *pb.GetCertificateRequest
	typ, name := parts[0], parts[1]
	switch typ {
	case "domainName":
		req = &pb.GetCertificateRequest{
			Domain:           name,
			WantOcspStapling: true,
		}
	case "certName":
		req = &pb.GetCertificateRequest{
			Name:             name,
			WantOcspStapling: true,
		}
	default:
		log.Infof("got invalid resourceName: %v", resourceName)
		err = status.Error(codes.InvalidArgument, "resourceName is invalid")
		return 0, "", nil, err
	}
	resp, err := srv.cs.GetCertificate(ctx, req)
	if err != nil {
		return 0, "", nil, err
	}

	tlsCert, err = utils.ToTLSCertificate([]byte(resp.Cert.PubKey), []byte(resp.Cert.PrivKey))
	if err != nil {
		return 0, "", nil, err
	}
	return pb.Certificate_Type(resp.Cert.Type), name, tlsCert, nil
}

func (srv *Service) versionInfo() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func (srv *Service) logRequest(ctx context.Context, r *discovery.DiscoveryRequest, msg string, start time.Time, err error, extra ...zap.Field) {
	duration := time.Since(start)
	fields := zlog.GetFields(ctx)
	fields = easy.Copy(fields, len(fields)+10)

	// overwrite start_time
	fields = append(fields,
		zap.Time("grpc.start_time", start),
		zap.Duration("grpc.duration", duration),
		zap.Int64("grpc.durationNsec", duration.Nanoseconds()),
	)
	if r != nil {
		fields = append(fields,
			zap.String("versionInfo", r.VersionInfo),
			zap.Strings("resourceNames", r.ResourceNames),
			zap.String("responseNonce", r.ResponseNonce),
		)
		if r.Node != nil {
			fields = append(fields,
				zap.String("node", r.Node.Id),
				zap.String("cluster", r.Node.Cluster))
		}
		if r.ErrorDetail != nil {
			fields = append(fields,
				zap.Int32("code", r.ErrorDetail.Code),
				zap.String("errDetail", r.ErrorDetail.Message))
		}
	}
	if len(extra) > 0 {
		fields = append(fields, extra...)
	}

	var infoLevel bool
	if len(extra) > 0 {
		infoLevel = true
		fields = append(fields, extra...)
	}
	if err != nil {
		fields = append(fields, zap.Error(err))
	}

	lg := srv.logger.With(fields...)
	switch {
	case err != nil || (r != nil && r.ErrorDetail != nil):
		lg.Error(msg, fields...)
	case infoLevel:
		lg.Info(msg, fields...)
	default:
		lg.Debug(msg, fields...)
	}
}

func (srv *Service) addRequestToContext(ctx context.Context, r *discovery.DiscoveryRequest) context.Context {
	var fields []zap.Field
	if r != nil {
		fields = []zap.Field{
			zap.String("versionInfo", r.VersionInfo),
			zap.Strings("resourceNames", r.ResourceNames),
			zap.String("responseNonce", r.ResponseNonce),
		}
		if r.Node != nil {
			fields = append(fields,
				zap.String("node", r.Node.Id),
				zap.String("cluster", r.Node.Cluster))
		}
		if r.ErrorDetail != nil {
			fields = append(fields,
				zap.Int32("code", r.ErrorDetail.Code),
				zap.String("errDetail", r.ErrorDetail.Message))
		}
	}
	return zlog.AddFields(ctx, fields...)
}
