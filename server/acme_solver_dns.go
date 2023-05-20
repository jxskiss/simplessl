package server

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/mholt/acmez/acme"

	"github.com/jxskiss/simplessl/pkg/config"
)

var dnsMu sync.Mutex

func NewDNSSolver(credential *config.DNSCredential) (*dnsSolver, error) {
	dnsMu.Lock()
	defer dnsMu.Unlock()

	for k, v := range credential.Env {
		err := os.Setenv(k, v)
		if err != nil {
			return nil, fmt.Errorf("dns solver: set env: %w", err)
		}
	}
	provider, err := dns.NewDNSChallengeProviderByName(credential.Provider)
	if err != nil {
		return nil, fmt.Errorf("dns solver: get provider: %w", err)
	}
	wait, _ := time.ParseDuration(credential.WaitDuration)
	return &dnsSolver{
		dnsProvider:  provider,
		waitDuration: wait,
	}, nil
}

type dnsSolver struct {
	dnsProvider  challenge.Provider
	waitDuration time.Duration
}

func (d *dnsSolver) Present(_ context.Context, chal acme.Challenge) error {
	return d.dnsProvider.Present(chal.Identifier.Value, chal.Token, chal.KeyAuthorization)
}

func (d *dnsSolver) CleanUp(_ context.Context, chal acme.Challenge) error {
	return d.dnsProvider.CleanUp(chal.Identifier.Value, chal.Token, chal.KeyAuthorization)
}

func (d *dnsSolver) Wait(ctx context.Context, _ acme.Challenge) error {
	wait := time.Second
	if d.waitDuration > 0 {
		wait = d.waitDuration
	} else {
		withTimeout, ok := d.dnsProvider.(challenge.ProviderTimeout)
		if ok {
			_, wait = withTimeout.Timeout()
		}
	}
	done := make(chan struct{})
	go func() {
		time.Sleep(wait)
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}
