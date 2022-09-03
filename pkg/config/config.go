package config

var DefaultSelfSignedOrganizations = []string{"SSL Cert Server Self-Signed"}

type Config struct {
	Version string `yaml:"version"`
	Listen  string `yaml:"listen" default:"127.0.0.1:8999"`
	PIDFile string `yaml:"pid_file" default:"ssl-cert-server.pid"`

	Storage struct {
		Type     string      `yaml:"type" default:"dir_cache"`
		DirCache string      `yaml:"dir_cache" default:"./secret-dir"`
		Redis    RedisConfig `yaml:"redis"`
	} `yaml:"storage"`

	SelfSigned struct {
		Enable          bool     `yaml:"enable"`
		CheckDomainName bool     `yaml:"check_domain_name"`
		Domains         []string `yaml:"domains"`
		DomainRegex     []string `yaml:"domain_regex"`
		ValidDays       int      `yaml:"valid_days"`
		Organization    string   `yaml:"organization"`
	} `yaml:"self_signed"`

	Managed struct {
		ReloadInterval string                `yaml:"reload_interval"`
		Certificates   []*ManagedCertificate `yaml:"certificates"`
	} `yaml:"managed"`

	ACME struct {
		DirectoryURL   string           `yaml:"directory_url" default:"https://acme-v02.api.letsencrypt.org/directory"`
		ForceRSA       bool             `yaml:"force_rsa"`
		RenewBefore    int              `yaml:"renew_before" default:"30"`
		DefaultAccount *ACMEAccount     `yaml:"default_account"`
		Accounts       []*ACMEAccount   `yaml:"accounts"`
		DNSCredentials []*DNSCredential `yaml:"dns_credentials"`

		OnDemand struct {
			Domains     []string `yaml:"domains"`
			DomainRegex []string `yaml:"domain_regex"`
		} `yaml:"on_demand"`

		Named struct {
			Certificates []*ACMECertificate `yaml:"certificates"`
		} `yaml:"named"`
	} `yaml:"acme"`

	state // prepared data
}

type RedisConfig struct {
	Addr   string `yaml:"addr" default:"127.0.0.1:6379"`
	Prefix string `yaml:"prefix"`
}

type ManagedCertificate struct {
	Name           string   `yaml:"name"`
	Domains        []string `yaml:"domains"`
	DomainRegex    []string `yaml:"domain_regex"`
	NoOCSPStapling bool     `yaml:"no_ocsp_stapling"`
}

type ACMEAccount struct {
	Email string `yaml:"email"`
}

type DNSCredential struct {
	Name         string            `yaml:"name"`
	Provider     string            `yaml:"provider"`
	WaitDuration string            `yaml:"wait_duration"`
	Env          map[string]string `yaml:"env"`
}

type ACMECertificate struct {
	Name          string   `yaml:"name"`
	Account       string   `yaml:"account"`
	DNSCredential string   `yaml:"dns_credential"`
	ForceRSA      bool     `yaml:"force_rsa"`
	Domains       []string `yaml:"domains"`
}
