package sds

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/jxskiss/gopkg/v2/utils/strutil"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/jxskiss/simplessl/pkg/pb"
	"github.com/jxskiss/simplessl/pkg/utils"
)

const secretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// isValidationContext returns if the given name is one of the predefined
// validation context names.
func isValidationContext(name string) bool {
	return name == ValidationContextName || name == ValidationContextAltName
}

// getDiscoveryResponse returns the api.DiscoveryResponse for the given request.
func getDiscoveryResponse(r *discovery.DiscoveryRequest, versionInfo string, certs []*tls.Certificate) (*discovery.DiscoveryResponse, error) {

	nonce := strutil.RandomHex(64)

	var i int
	var b []byte
	var err error
	var resources []*anypb.Any
	for _, name := range r.ResourceNames {
		if isValidationContext(name) {
			err = errors.New("validationContext support not implemented")
			return nil, err
		} else {
			b, err = getCertificateChain(name, certs[i])
			i++
		}
		if err != nil {
			return nil, err
		}
		resources = append(resources, &anypb.Any{
			TypeUrl: secretTypeURL,
			Value:   b,
		})
	}

	return &discovery.DiscoveryResponse{
		VersionInfo: versionInfo,
		Resources:   resources,
		Canary:      false,
		TypeUrl:     secretTypeURL,
		Nonce:       nonce,
		ControlPlane: &core.ControlPlane{
			Identifier: Identifier,
		},
	}, nil
}

// nolint: unused
func getTrustedCA(name string, roots []*x509.Certificate) ([]byte, error) {
	var chain bytes.Buffer
	for _, crt := range roots {
		chain.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}))
	}
	secret := auth.Secret{
		Name: name,
		Type: &auth.Secret_ValidationContext{
			ValidationContext: &auth.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{InlineBytes: chain.Bytes()},
				},
			},
		},
	}
	v, err := proto.Marshal(&secret)
	return v, errors.Wrapf(err, "error marshaling secret")
}

func getCertificateChain(name string, cert *tls.Certificate) ([]byte, error) {
	var chain bytes.Buffer
	for _, c := range cert.Certificate {
		chain.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c,
		}))
	}

	privKeyBlock := utils.ToPEMBlock(cert.PrivateKey)
	tlsCertificate := &auth.TlsCertificate{
		CertificateChain: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{InlineBytes: chain.Bytes()},
		},
		PrivateKey: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{InlineBytes: pem.EncodeToMemory(privKeyBlock)},
		},
		// Password protected keys are not supported at the moment
		// Password: &core.DataSource{
		// 	Specifier: &core.DataSource_InlineBytes{InlineBytes: nil},
		// },
	}
	if len(cert.OCSPStaple) > 0 {
		tlsCertificate.OcspStaple = &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{InlineBytes: cert.OCSPStaple},
		}
	}

	secret := auth.Secret{
		Name: name,
		Type: &auth.Secret_TlsCertificate{
			TlsCertificate: tlsCertificate,
		},
	}

	v, err := proto.Marshal(&secret)
	return v, errors.Wrapf(err, "error marshaling secret")
}

func toTLSCertificate(resp *pb.GetCertificateResponse) (*tls.Certificate, error) {
	certPEM := []byte(resp.Cert.PubKey)
	keyPEM := []byte(resp.Cert.PrivKey)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert.OCSPStaple = resp.GetOcspStapling().GetRaw()
	return &cert, nil
}
