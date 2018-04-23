package rootcerts

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Config 配置LoadCACerts方法从何处加载证书文件
type Config struct {
	// CAFile 指定的地址将优先于CAPath
	CAFile string
	CAPath string
}

// ConfigureTLS 为给定的tls.Config设置根证书
func ConfigureTLS(t *tls.Config, c *Config) error {
	if t == nil {
		return nil
	}

	pool, err := LoadCACerts(c)
	if err != nil {
		return err
	}
	t.RootCAs = pool
	return nil
}

// LoadCACerts 生成一个CertPool
func LoadCACerts(c *Config) (*x509.CertPool, error) {
	if c == nil {
		c = &Config{}
	}

	if c.CAFile != "" {
		return LoadCAFile(c.CAFile)
	}
	if c.CAPath != "" {
		return LoadCAPath(c.CAPath)
	}

	return LoadSystemCAs()
}

// LoadCAFile 加载一个单独的证书文件
func LoadCAFile(caFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	pem, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA File: %s", err)
	}

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", caFile)
	}

	return pool, nil
}

// LoadCAPath 加载指定路径下的所有证书
func LoadCAPath(caPath string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		pem, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Error loading file from CAPath: %s", err)
		}

		ok := pool.AppendCertsFromPEM(pem)
		if !ok {
			return fmt.Errorf("Error loading CA Path: Couldn't parse PEM in: %s", path)
		}

		return nil
	}

	err := filepath.Walk(caPath, walkFn)
	if err != nil {
		return nil, err
	}
	return pool, nil
}
