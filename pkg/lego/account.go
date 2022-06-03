package lego

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"

	"golang.org/x/crypto/acme"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

// Account represents a users local saved credentials.
type Account struct {
	Email string `json:"email"`

	Registration struct {
		Body struct {
			Status                 string          `json:"status,omitempty"`
			Contact                []string        `json:"contact,omitempty"`
			ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
		} `json:"body,omitempty"`

		URI string `json:"uri,omitempty"`
	} `json:"registration"`

	Key *ecdsa.PrivateKey `json:"-"`
}

func FromACMEAccount(email string, acc *acme.Account, key *ecdsa.PrivateKey) (*Account, error) {
	out := &Account{
		Email: email,
		Key:   key,
	}
	out.Registration.URI = acc.URI
	out.Registration.Body.Status = acc.Status
	out.Registration.Body.Contact = acc.Contact

	if acc.ExternalAccountBinding != nil {
		buf, err := json.Marshal(acc.ExternalAccountBinding)
		if err != nil {
			return nil, err
		}
		out.Registration.Body.ExternalAccountBinding = buf
	}
	return out, nil
}

func (acc *Account) AccountFilePath() string {
	u, _ := url.Parse(acc.Registration.URI)
	return filepath.Join("accounts", u.Host, acc.Email, "account.json")
}

func (acc *Account) KeyFilePath() string {
	u, _ := url.Parse(acc.Registration.URI)
	return filepath.Join("accounts", u.Host, acc.Email, "keys", acc.Email+".key")
}

func (acc *Account) Save(rootPath string) (err error) {
	keyBuf := &bytes.Buffer{}
	_ = utils.EncodeECDSAKey(keyBuf, acc.Key)
	keyPEM := keyBuf.Bytes()
	keyFile := filepath.Join(rootPath, acc.KeyFilePath())
	err = writeFile(keyFile, keyPEM, 0600)
	if err != nil {
		return fmt.Errorf("cannot write private key file: %w", err)
	}

	accBytes, err := json.MarshalIndent(acc, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal account: %w", err)
	}
	accFile := filepath.Join(rootPath, acc.AccountFilePath())
	err = writeFile(accFile, accBytes, 0600)
	if err != nil {
		return fmt.Errorf("cannot write account file: %w", err)
	}

	return nil
}
