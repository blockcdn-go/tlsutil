// +build !darwin

package rootcerts

import (
	"crypto/x509"
)

// LoadSystemCAs 在非Darwin系统上不做任何操作
func LoadSystemCAs() (*x509.CertPool, error) {
	return nil, nil
}
