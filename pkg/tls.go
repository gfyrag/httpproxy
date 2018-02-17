package httpproxy

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
	"crypto/rsa"
	"sync"
	"crypto"
)

//
// https://ericchiang.github.io/post/go-tls/
//

func serialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	return serialNumber
}

func CATemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{
			CommonName: "httpproxy",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour*24*365),
		BasicConstraintsValid: true,
		IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
}

func CertTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour*24*365),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

func CACert(privateKey crypto.Signer, tpl *x509.Certificate) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, tpl, tpl, privateKey.Public(), privateKey)
}

func ManagedCertPool(privateKey crypto.Signer, caCert *x509.Certificate) (*tls.Config, error) {

	var (
		privateKeyBytes []byte
		err error
		signatureAlgorithm x509.SignatureAlgorithm
	)
	switch pp := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(pp)
		signatureAlgorithm = x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		privateKeyBytes, err = x509.MarshalECPrivateKey(pp)
		signatureAlgorithm = x509.ECDSAWithSHA256
	default:
		panic("not supported")
	}
	if err != nil {
		return nil, err
	}

	caCert.SignatureAlgorithm = signatureAlgorithm

	certs := make(map[string]tls.Certificate)
	mu := sync.Mutex{}
	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()

			cert, ok := certs[info.ServerName]
			if !ok {
				tpl := caCert
				tpl.Subject = pkix.Name{
					CommonName: info.ServerName,
				}

				certDer, err := x509.CreateCertificate(
					rand.Reader,
					CertTemplate(info.ServerName),
					caCert,
					privateKey.Public(),
					privateKey,
				)
				if err != nil {
					return nil, err
				}

				cert, err = tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{
					Type: "CERTIFICATE",
					Bytes: certDer,
				}), pem.EncodeToMemory(&pem.Block{
					Type: "RSA PRIVATE KEY",
					Bytes: privateKeyBytes,
				}))
				if err != nil {
					return nil, err
				}
			}
			certs[info.ServerName] = cert
			return &cert, nil
		},
	}, nil
}

func RSA() (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ca := CATemplate()
	_, err = CACert(privateKey, ca)
	if err != nil {
		return nil, err
	}
	return ManagedCertPool(privateKey, ca)
}

func MustRSA() *tls.Config {
	rsa, err := RSA()
	if err != nil {
		panic(err)
	}
	return rsa
}

func ECDSA() (*tls.Config, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ca := CATemplate()
	_, err = CACert(privateKey, ca)
	if err != nil {
		return nil, err
	}
	return ManagedCertPool(privateKey, ca)
}