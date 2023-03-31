package server

import "errors"

const (
	CodeBadRequest    = 1000
	CodeNoContent     = 1001
	CodeInternalError = 1002
)

var (
	ErrInvalidRequestData       = errors.New("invalid request data")
	ErrInvalidDomainName        = errors.New("invalid domain name")
	ErrHostNotPermitted         = errors.New("host name not permitted")
	ErrCertificateIsExpired     = errors.New("certificate is expired")
	ErrGetCertificate           = errors.New("cannot get certificate")
	ErrMarshalCertificate       = errors.New("cannot marshal certificate")
	ErrOCSPStaplingNotCached    = errors.New("OCSP stapling not cached")
	ErrOCSPStaplingNotSupported = errors.New("OCSP stapling not supported")
)
