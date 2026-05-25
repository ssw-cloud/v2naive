package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

func RequestCert(cert *panel.CertInfo) error {
	switch cert.CertMode {
	case "", "none":
		if fileExists(cert.CertFile) && fileExists(cert.KeyFile) {
			return nil
		}
		if cert.CertDomain == "" {
			return fmt.Errorf("empty cert domain for self-signed certificate")
		}
		return generateSelfSigned(cert.CertDomain, cert.CertFile, cert.KeyFile)
	case "file":
		if !fileExists(cert.CertFile) || !fileExists(cert.KeyFile) {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		return nil
	case "dns", "http":
		if fileExists(cert.CertFile) && fileExists(cert.KeyFile) {
			return nil
		}
		legoClient, err := NewLego(cert)
		if err != nil {
			return err
		}
		return legoClient.CreateCert()
	case "self":
		if fileExists(cert.CertFile) && fileExists(cert.KeyFile) {
			return nil
		}
		if cert.CertDomain == "" {
			return fmt.Errorf("empty cert domain for self-signed certificate")
		}
		return generateSelfSigned(cert.CertDomain, cert.CertFile, cert.KeyFile)
	default:
		return fmt.Errorf("unsupported cert mode: %s", cert.CertMode)
	}
}

func generateSelfSigned(domain, certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return err
	}
	if err := ensureDir(certPath); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}), 0644); err != nil {
		return err
	}
	if err := ensureDir(keyPath); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0600)
}

type Lego struct {
	client *lego.Client
	config *panel.CertInfo
}

func NewLego(config *panel.CertInfo) (*Lego, error) {
	user, err := newLegoUser(path.Join(path.Dir(config.CertFile), "user", fmt.Sprintf("user-%s.json", config.Email)), config.Email)
	if err != nil {
		return nil, err
	}
	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}
	l := &Lego{client: client, config: config}
	if err := l.setProvider(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Lego) setProvider() error {
	switch l.config.CertMode {
	case "http":
		return l.client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	case "dns":
		for key, value := range l.config.DNSEnv {
			os.Setenv(key, value)
		}
		provider, err := dns.NewDNSChallengeProviderByName(l.config.Provider)
		if err != nil {
			return err
		}
		return l.client.Challenge.SetDNS01Provider(provider)
	default:
		return nil
	}
}

func (l *Lego) CreateCert() error {
	resource, err := l.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{l.config.CertDomain},
		Bundle:  true,
	})
	if err != nil {
		return err
	}
	return l.writeCert(resource)
}

func (l *Lego) RenewCert() error {
	content, err := os.ReadFile(l.config.CertFile)
	if err != nil {
		return err
	}
	cert, err := certcrypto.ParsePEMCertificate(content)
	if err != nil {
		return err
	}
	if int(time.Until(cert.NotAfter).Hours()/24.0) > 30 {
		return nil
	}
	resource, err := l.client.Certificate.Renew(certificate.Resource{
		Domain:      l.config.CertDomain,
		Certificate: content,
	}, true, false, "")
	if err != nil {
		return err
	}
	return l.writeCert(resource)
}

func (l *Lego) writeCert(resource *certificate.Resource) error {
	if err := ensureDir(l.config.CertFile); err != nil {
		return err
	}
	if err := os.WriteFile(l.config.CertFile, resource.Certificate, 0644); err != nil {
		return err
	}
	if err := ensureDir(l.config.KeyFile); err != nil {
		return err
	}
	return os.WriteFile(l.config.KeyFile, resource.PrivateKey, 0600)
}

type legoUser struct {
	Email        string                 `json:"Email"`
	Registration *registration.Resource `json:"Registration"`
	KeyEncoded   string                 `json:"Key"`
	key          crypto.PrivateKey
}

func (u *legoUser) GetEmail() string {
	return u.Email
}

func (u *legoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *legoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func newLegoUser(filePath, email string) (*legoUser, error) {
	user := &legoUser{}
	if fileExists(filePath) {
		if err := user.Load(filePath); err != nil {
			return nil, err
		}
		if user.Email == email {
			return user, nil
		}
	}
	user.Email = email
	if err := registerLegoUser(user, filePath); err != nil {
		return nil, err
	}
	return user, nil
}

func registerLegoUser(user *legoUser, filePath string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	user.key = privateKey
	legoConfig := lego.NewConfig(user)
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return err
	}
	registration, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	user.Registration = registration
	return user.Save(filePath)
}

func (u *legoUser) Save(filePath string) error {
	if err := ensureDir(filePath); err != nil {
		return err
	}
	encoded, err := encodePrivate(u.key.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	u.KeyEncoded = encoded
	defer func() {
		u.KeyEncoded = ""
	}()
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(u)
}

func (u *legoUser) Load(filePath string) error {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(file, u); err != nil {
		return err
	}
	return u.decodePrivate(u.KeyEncoded)
}

func encodePrivate(privKey *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})), nil
}

func (u *legoUser) decodePrivate(pemEncoded string) error {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return fmt.Errorf("invalid private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	u.key = key
	return nil
}

func ensureDir(filePath string) error {
	dir := path.Dir(filePath)
	return os.MkdirAll(dir, 0755)
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func ParseDNSPairs(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	for _, pair := range strings.Split(raw, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			out[kv[0]] = kv[1]
		}
	}
	return out
}
