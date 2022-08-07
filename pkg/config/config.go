package config

var DefaultSelfSignedOrganizations = []string{"SSL Cert Server Self-Signed"}

type Config struct {
	Version string `yaml:"version"`
	Listen  string `yaml:"listen" default:"127.0.0.1:8999"`
	PIDFile string `yaml:"pidFile" default:"ssl-cert-server.pid"`

	Storage struct {
		Type     string      `yaml:"type" default:"dir_cache"`
		DirCache string      `yaml:"dirCache" default:"./secret-dir"`
		Redis    RedisConfig `yaml:"redis"`
	} `yaml:"storage"`

	SelfSigned struct {
		Enable          bool     `yaml:"enable"`
		CheckDomainName bool     `yaml:"checkDomainName"`
		Domains         []string `yaml:"domains"`
		DomainRegex     []string `yaml:"domainRegex"`
		ValidDays       int      `yaml:"validDays"`
		Organization    string   `yaml:"organization"`
	} `yaml:"selfSigned"`

	Managed struct {
		ReloadInterval string                `yaml:"reloadInterval"`
		Certificates   []*ManagedCertificate `yaml:"certificates"`
	} `yaml:"managed"`

	ACME struct {
		DirectoryURL   string           `yaml:"directoryURL"`
		ForceRSA       bool             `yaml:"forceRSA"`
		RenewBefore    int              `yaml:"renewBefore"`
		DefaultAccount *ACMEAccount     `yaml:"defaultAccount"`
		Accounts       []*ACMEAccount   `yaml:"accounts"`
		DNSCredentials []*DNSCredential `yaml:"dnsCredentials"`

		OnDemand struct {
			Domains     []string `yaml:"domains"`
			DomainRegex []string `yaml:"domainRegex"`
		} `yaml:"onDemand"`

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
	DomainRegex    []string `yaml:"domainRegex"`
	NoOCSPStapling bool     `yaml:"noOCSPStapling"`
}

type ACMEAccount struct {
	Email string `yaml:"email"`
}

type DNSCredential struct {
	Name         string            `yaml:"name"`
	Provider     string            `yaml:"provider"`
	WaitDuration string            `yaml:"waitDuration"`
	Env          map[string]string `yaml:"env"`
}

type ACMECertificate struct {
	Name          string   `yaml:"name"`
	Account       string   `yaml:"account"`
	DNSCredential string   `yaml:"dnsCredential"`
	ForceRSA      bool     `yaml:"forceRSA"`
	Domains       []string `yaml:"domains"`
}
