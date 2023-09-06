package jks

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"strings"
)

func transformPemCertsToKeystoreCert(certs []string) ([]keystore.Certificate, error) {
	keystoreCerts := []keystore.Certificate{}
	for i, cert := range certs {
		cert = strings.TrimSpace(cert)
		block, rest := pem.Decode([]byte(cert))
		if len(rest) > 0 {
			return nil, fmt.Errorf("%d pem file containes more than one cert", i)
		}
		if block == nil {
			return nil, fmt.Errorf("%d pem file does not contains cert", i)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%d pem file does not contains CERTIFICATE file (it contains %s)", i, block.Type)
		}
		keystoreCerts = append(keystoreCerts, keystore.Certificate{
			Type:    "X.509",
			Content: block.Bytes,
		})
	}
	return keystoreCerts, nil
}

func decodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding private key PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs#8 private key: %s", err.Error())
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("error parsing pkcs#8 private key: invalid key type")
		}
		return signer, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key: %s", err.Error())
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing rsa private key: %s", err.Error())
		}

		err = key.Validate()
		if err != nil {
			return nil, fmt.Errorf("rsa private key failed validation: %s", err.Error())
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unknown private key type: %s", block.Type)
	}
}
