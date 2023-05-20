package server

import (
	"fmt"

	"github.com/jxskiss/simplessl/pkg/pb"
)

func getCertKey(certTyp pb.Certificate_Type, certName string) string {
	return fmt.Sprintf("%d:%s", int(certTyp), certName)
}
