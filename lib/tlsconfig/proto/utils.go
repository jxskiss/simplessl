package proto

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	CodeBadRequest    = "drpcerr(1000)"
	CodeNoContent     = "drpcerr(1001)"
	CodeInternalError = "drpcerr(1002)"
)

func (p *ErrorCode) Error() string {
	return fmt.Sprintf("%d %s %s", p.statusCode, p.Code, p.Msg)
}

func DecodeError(statusCode int, body io.Reader) error {
	var errCode ErrorCode
	errCode.statusCode = statusCode
	jsonErr := json.NewDecoder(body).Decode(&errCode)
	if jsonErr != nil {
		return jsonErr
	}
	return &errCode
}
