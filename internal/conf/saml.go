package conf

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// SAMLConfiguration holds configuration for native SAML support.
type SAMLConfiguration struct {
	Enabled                  bool          `json:"enabled"`
	PrivateKey               string        `json:"-" split_words:"true"`
	RelayStateValidityPeriod time.Duration `json:"relay_state_validity_period" split_words:"true"`

	RSAPrivateKey *rsa.PrivateKey   `json:"-"`
	RSAPublicKey  *rsa.PublicKey    `json:"-"`
	Certificate   *x509.Certificate `json:"-"`

	ExternalURL string `json:"external_url,omitempty" split_words:"true"`

	RateLimitAssertion float64 `default:"15" split_words:"true"`
}

func (c *SAMLConfiguration) Validate() error {
	if c.Enabled {
		bytes, err := base64.StdEncoding.DecodeString(c.PrivateKey)
		if err != nil {
			return errors.New("SAML private key not in standard Base64 format")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(bytes)
		if err != nil {
			return errors.New("SAML private key not in PKCS#1 format")
		}

		err = privateKey.Validate()
		if err != nil {
			return errors.New("SAML private key is not valid")
		}

		if privateKey.E != 0x10001 {
			return errors.New("SAML private key should use the 65537 (0x10001) RSA public exponent")
		}

		if privateKey.N.BitLen() < 2048 {
			return errors.New("SAML private key must be at least RSA 2048")
		}

		if c.RelayStateValidityPeriod < 0 {
			return errors.New("SAML RelayState validity period should be a positive duration")
		}

		if c.ExternalURL != "" {
			_, err := url.ParseRequestURI(c.ExternalURL)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// PopulateFields fills the configuration details based off the provided
// parameters.
func (c *SAMLConfiguration) PopulateFields(externalURL string) error {
	// errors are intentionally ignored since they should have been handled
	// within #Validate()
	bytes, _ := base64.StdEncoding.DecodeString(c.PrivateKey)
	privateKey, _ := x509.ParsePKCS1PrivateKey(bytes)

	c.RSAPrivateKey = privateKey
	c.RSAPublicKey = privateKey.Public().(*rsa.PublicKey)

	parsedURL, err := url.ParseRequestURI(externalURL)
	if err != nil {
		return fmt.Errorf("saml: unable to parse external URL for SAML, check API_EXTERNAL_URL: %w", err)
	}

	host := ""
	host, _, err = net.SplitHostPort(parsedURL.Host)
	if err != nil {
		host = parsedURL.Host
	}

	// SAML does not care much about the contents of the certificate, it
	// only uses it as a vessel for the public key; therefore we set these
	// fixed values.
	// Please avoid modifying or adding new values to this template as they
	// will change the exposed SAML certificate, requiring users of
	// GoTrue to re-establish a connection between their Identity Provider
	// and their running GoTrue instances.
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		IsCA:         false,
		DNSNames: []string{
			"_samlsp." + host,
		},
		KeyUsage:  x509.KeyUsageDigitalSignature,
		NotBefore: time.UnixMilli(0).UTC(),
		NotAfter:  time.UnixMilli(0).UTC().AddDate(200, 0, 0),
		Subject: pkix.Name{
			CommonName: "SAML 2.0 Certificate for " + host,
		},
	}

	certDer, err := x509.CreateCertificate(nil, certTemplate, certTemplate, c.RSAPublicKey, c.RSAPrivateKey)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return err
	}

	c.Certificate = cert

	if c.RelayStateValidityPeriod == 0 {
		c.RelayStateValidityPeriod = 2 * time.Minute
	}

	return nil
}
