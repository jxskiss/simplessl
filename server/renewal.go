package server

import (
	"context"
)

type CertRenewManager interface {
	Watch(ctx context.Context, key string, getCert CertFunc)
}

type certRenewal struct {
}
