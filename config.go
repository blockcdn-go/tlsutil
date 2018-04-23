package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/blockcdn-go/tlsutil/rootcerts"
)

// TLSLookup 保存tls协议的各个版本
var TLSLookup = map[string]uint16{
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
}

// Config 用于创建tls.Config
type Config struct {
	// VerifyIncoming 用于验证传入连接的真实性。
	VerifyIncoming bool

	// VerifyServerHostname 用于启用服务器端的主机名验证
	VerifyServerHostname bool

	CAFile                   string
	CAPath                   string
	CertFile                 string
	KeyFile                  string
	ServerName               string
	TLSMinVersion            string
	CipherSuites             []uint16
	PreferServerCipherSuites bool
}

// AppendCA 打开并解析证书文件，并将证书添加到CertPool中
func (c *Config) AppendCA(pool *x509.CertPool) error {
	if c.CAFile == "" {
		return nil
	}

	data, err := ioutil.ReadFile(c.CAFile)
	if err != nil {
		return fmt.Errorf("Failed to read CA file: %v", err)
	}

	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("Failed to parse any CA certificates")
	}

	return nil
}

// KeyPair 用于打开并解析一对证书和私钥文件
func (c *Config) KeyPair() (*tls.Certificate, error) {
	if c.CertFile == "" || c.KeyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to load cert/key pair: %v", err)
	}
	return &cert, nil
}

// IncomingTLSConfig 为传入请求生成tls配置
func (c *Config) IncomingTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName: c.ServerName,
		ClientCAs:  x509.NewCertPool(),
		ClientAuth: tls.NoClientCert,
	}

	if len(c.CipherSuites) != 0 {
		tlsConfig.CipherSuites = c.CipherSuites
	}
	if c.PreferServerCipherSuites {
		tlsConfig.PreferServerCipherSuites = true
	}

	if c.CAFile != "" {
		pool, err := rootcerts.LoadCAFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	} else if c.CAPath != "" {
		pool, err := rootcerts.LoadCAPath(c.CAPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}

	cert, err := c.KeyPair()
	if err != nil {
		return nil, err
	} else if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	if c.VerifyIncoming {
		tlsConfig.ClientAuth = tls.RequestClientCert
		if c.CAFile == "" && c.CAPath == "" {
			return nil, fmt.Errorf("VerifyIncoming set, and no CA certificate provided")
		}
		if cert == nil {
			return nil, fmt.Errorf("VerifyIncoming set, and no Cert/Key pair provided")
		}
	}

	if c.TLSMinVersion != "" {
		tlsvers, ok := TLSLookup[c.TLSMinVersion]
		if !ok {
			return nil, fmt.Errorf("TLSMinVersion: value %s not supported, please specify one of [tls10,tls11,tls12]", c.TLSMinVersion)
		}
		tlsConfig.MinVersion = tlsvers
	}
	return tlsConfig, nil
}

// ParseCiphers 将加密套件字符串解析成数组
func ParseCiphers(cipherStr string) ([]uint16, error) {
	suites := []uint16{}

	cipherStr = strings.TrimSpace(cipherStr)
	if cipherStr == "" {
		return []uint16{}, nil
	}
	ciphers := strings.Split(cipherStr, ",")

	cipherMap := map[string]uint16{
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}

	for _, cipher := range ciphers {
		if v, ok := cipherMap[cipher]; ok {
			suites = append(suites, v)
		} else {
			return suites, fmt.Errorf("unsupported cipher %q", cipher)
		}
	}

	return suites, nil
}
