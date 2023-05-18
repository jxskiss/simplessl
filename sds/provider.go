package sds

import (
	"context"

	"github.com/jxskiss/ssl-cert-server/pkg/pb"
)

type CertProviderFunc func(context.Context, *pb.GetCertificateRequest) (
	resp *pb.GetCertificateResponse, certKey string, err error)
