package config

type v1Config struct {
	Listen  string `yaml:"listen" default:"127.0.0.1:8999"`
	PIDFile string `yaml:"pid_file" default:"ssl-cert-server.pid"`

	Storage struct {
		Type     string      `yaml:"type" default:"dir_cache"`
		DirCache string      `yaml:"dir_cache" default:"./secret-dir"`
		Redis    RedisConfig `yaml:"redis"`
	} `yaml:"storage"`

	Managed []struct {
		Pattern string `yaml:"pattern"`
		CertKey string `yaml:"cert_key"`
	} `yaml:"managed"`

	LetsEncrypt struct {
		Staging     bool     `yaml:"staging"`   // default: false
		ForceRSA    bool     `yaml:"force_rsa"` // default: false
		RenewBefore int      `yaml:"renew_before" default:"30"`
		Email       string   `yaml:"email"`
		Domains     []string `yaml:"domains"`
		REPatterns  []string `yaml:"re_patterns"`
	} `yaml:"lets_encrypt"`

	Wildcard struct {
		LegoDataPath   string            `yaml:"lego_data_path"`
		DNSCredentials []*DNSCredential  `yaml:"dns_credentials"`
		Certificates   []*v1WildcardItem `yaml:"certificates"`
	} `yaml:"wildcard"`

	SelfSigned struct {
		Enable       bool     `yaml:"enable"`    // default: false
		CheckSNI     bool     `yaml:"check_sni"` // default: false
		ValidDays    int      `yaml:"valid_days" default:"365"`
		Organization []string `yaml:"organization"`
		CertKey      string   `yaml:"cert_key" default:"self_signed"`
	} `yaml:"self_signed"`
}

type v1WildcardItem struct {
	RootDomain string   `yaml:"root_domain"`
	Credential string   `yaml:"credential"`
	Domains    []string `yaml:"domains"`
}

func (c *v1Config) ToV2Config() *Config {
	v2Cfg := &Config{
		Version: "1",
		Listen:  c.Listen,
		PIDFile: c.PIDFile,
	}

	// storage
	v2Cfg.Storage.Type = c.Storage.Type
	v2Cfg.Storage.DirCache = c.Storage.DirCache
	v2Cfg.Storage.Redis = c.Storage.Redis

	// self-signed
	v2Cfg.SelfSigned.Enable = c.SelfSigned.Enable
	v2Cfg.SelfSigned.ValidDays = c.SelfSigned.ValidDays
	if len(c.SelfSigned.Organization) > 0 {
		v2Cfg.SelfSigned.Organization = c.SelfSigned.Organization[0]
	}

	// managed
	for _, x := range c.Managed {
		v2Cert := &ManagedCertificate{
			Name:        x.CertKey,
			DomainRegex: []string{x.Pattern},
		}
		v2Cfg.Managed.Certificates = append(v2Cfg.Managed.Certificates, v2Cert)
	}

	// acme
	v2Cfg.ACME.DirectoryURL = LetsEncryptURL
	if c.LetsEncrypt.Staging {
		v2Cfg.ACME.DirectoryURL = LetsEncryptStagingURL
	}
	v2Cfg.ACME.ForceRSA = c.LetsEncrypt.ForceRSA
	v2Cfg.ACME.RenewBefore = c.LetsEncrypt.RenewBefore
	v2Cfg.ACME.DefaultAccount = &ACMEAccount{
		Email: c.LetsEncrypt.Email,
	}
	v2Cfg.ACME.OnDemand.Domains = c.LetsEncrypt.Domains
	v2Cfg.ACME.OnDemand.DomainRegex = c.LetsEncrypt.REPatterns
	v2Cfg.ACME.DNSCredentials = c.Wildcard.DNSCredentials

	// named certificates
	for _, x := range c.Wildcard.Certificates {
		v2Cert := &ACMECertificate{
			Name:          x.RootDomain,
			DNSCredential: x.Credential,
			Domains:       x.Domains,
		}
		v2Cfg.ACME.Named.Certificates = append(v2Cfg.ACME.Named.Certificates, v2Cert)
	}

	return v2Cfg
}
