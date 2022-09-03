package proto

type Certificate_Type int

const (
	Certificate_UNKNOWN        Certificate_Type = 0
	Certificate_ALPN           Certificate_Type = 1
	Certificate_SELF_SIGNED    Certificate_Type = 2
	Certificate_MANAGED        Certificate_Type = 3
	Certificate_ACME_ON_DEMAND Certificate_Type = 11
	Certificate_ACME_NAMED     Certificate_Type = 12
)

type Certificate struct {
	Type            Certificate_Type `json:"type,omitempty"`
	PubKey          string           `json:"pubKey,omitempty"`
	PrivKey         string           `json:"privKey,omitempty"`
	Fp              string           `json:"fp,omitempty"`
	NotBeforeSec    int64            `json:"notBeforeSec,string,omitempty"`
	NotAfterSec     int64            `json:"notAfterSec,string,omitempty"`
	TtlSec          int64            `json:"ttlSec,string,omitempty"`
	HasOcspStapling bool             `json:"hasOcspStapling,omitempty"`
}

type OCSPStapling struct {
	Raw           []byte `json:"raw,omitempty"`
	NextUpdateSec int64  `json:"nextUpdateSec,string,omitempty"`
	TtlSec        int64  `json:"ttlSec,string,omitempty"`
}

type GetCertificateRequest struct {
	Domain           string `json:"domain,omitempty"`
	Name             string `json:"name,omitempty"`
	IsAlpn           bool   `json:"isAlpn,omitempty"`
	WantOcspStapling bool   `json:"wantOcspStapling,omitempty"`
}

type GetCertificateResponse struct {
	Cert         *Certificate  `json:"cert,omitempty"`
	OcspStapling *OCSPStapling `json:"ocspStapling,omitempty"`
}

type GetOCSPStaplingRequest struct {
	Domain      string `json:"domain,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type GetOCSPStaplingResponse struct {
	OcspStapling *OCSPStapling `json:"ocspStapling,omitempty"`
}

type ErrorCode struct {
	statusCode int

	Code string `json:"code,omitempty"`
	Msg  string `json:"msg,omitempty"`
}
