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

func caCert() *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{
			CommonName: "httpproxy",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour*24*365),
		BasicConstraintsValid: true,
	}
	tpl.IsCA = true
	tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	return tpl
}

func managedCertPool(privateKey crypto.Signer, privateKeyBytes []byte, publicKey crypto.PublicKey, signatureAlgorithm x509.SignatureAlgorithm) *tls.Config {
	baseTpl := caCert()
	baseTpl.SignatureAlgorithm = signatureAlgorithm

	certs := make(map[string]tls.Certificate)
	mu := sync.Mutex{}
	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()

			cert, ok := certs[info.ServerName]
			if !ok {
				tpl := *baseTpl
				tpl.Subject = pkix.Name{
					CommonName: info.ServerName,
				}

				certDer, err := x509.CreateCertificate(
					rand.Reader,
					&tpl,
					baseTpl,
					publicKey,
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
	}
}

func RSA() (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	return managedCertPool(privateKey, privateKeyBytes, privateKey.Public(), x509.SHA256WithRSA), nil
}

func ECDSA() (*tls.Config, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return managedCertPool(privateKey, privateKeyBytes, privateKey.Public(), x509.ECDSAWithSHA256), nil
}