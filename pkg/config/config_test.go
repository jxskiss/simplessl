package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExampleConfig(t *testing.T) {
	exampleCfg, err := LoadConfig("../../example.conf.yaml")
	assert.Nil(t, err)

	assert.Equal(t, exampleCfg.Version, Version2)
	assert.NotZero(t, exampleCfg.Listen)
	assert.NotZero(t, exampleCfg.PIDFile)
	assert.NotZero(t, exampleCfg.Storage)
	assert.NotZero(t, exampleCfg.SelfSigned)
	assert.NotZero(t, exampleCfg.Managed)
	assert.NotZero(t, exampleCfg.ACME)

	assert.Equal(t, exampleCfg.Managed.ReloadInterval, "10m")
	assert.True(t, len(exampleCfg.Managed.Certificates) > 1)
	assert.True(t, len(exampleCfg.managedCertMap) > 1)

	assert.NotZero(t, exampleCfg.ACME.DirectoryURL)
	assert.NotZero(t, exampleCfg.ACME.DefaultAccount)
	assert.NotZero(t, exampleCfg.ACME.Accounts)
	assert.NotZero(t, exampleCfg.ACME.DNSCredentials)
	assert.NotZero(t, exampleCfg.ACME.OnDemand)
	assert.NotZero(t, exampleCfg.ACME.Named)
	assert.True(t, len(exampleCfg.acmeAccountMap) > 1)
	assert.True(t, len(exampleCfg.dnsCredentialMap) > 1)
	assert.True(t, len(exampleCfg.acmeNamedCertMap) > 1)
}
