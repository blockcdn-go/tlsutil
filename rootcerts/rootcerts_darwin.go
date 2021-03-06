package rootcerts

import (
	"crypto/x509"
	"os/exec"
	"path"

	"github.com/blockcdn-go/home"
)

// LoadSystemCAs 在Darwin系统上的操作
func LoadSystemCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, keychain := range certKeychains() {
		err := addCertsFromKeychain(pool, keychain)
		if err != nil {
			return nil, err
		}
	}

	return pool, nil
}

func addCertsFromKeychain(pool *x509.CertPool, keychain string) error {
	cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain)
	data, err := cmd.Output()
	if err != nil {
		return err
	}

	pool.AppendCertsFromPEM(data)
	return nil
}

func certKeychains() []string {
	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}

	home, err := home.Dir()
	if err == nil {
		loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")
		keychains = append(keychains, loginKeychain)
	}

	return keychains
}
