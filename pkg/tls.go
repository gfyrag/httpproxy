package httpproxy

import (
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/crypto/acme"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"context"
	"net/http"
	"strconv"
	"net"
	"crypto/x509/pkix"
	"encoding/pem"
	"bytes"
	"errors"
	"math/big"
	"time"
	"crypto/rsa"
)

//
// https://ericchiang.github.io/post/go-tls/
//

func caCert(domain string) *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{
			CommonName: domain,
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

type RSAConfig struct {
	Domain string
}

func RSA(cfg RSAConfig) (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	tpl := caCert(cfg.Domain)
	tpl.SignatureAlgorithm = x509.SHA256WithRSA
	certDer, err := x509.CreateCertificate(
		rand.Reader,
		tpl,
		tpl,
		privateKey.Public(),
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: certDer,
	}), pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{cert},
	}, nil
}

var (
	ErrHTTPChallengeNotFound = errors.New("http challenge not found")
)

type ACMEConfig struct {
	Url string
	Email string
	Domain string
}

func ACME(ctx context.Context, cfg ACMEConfig) (*tls.Config, error) {
	var err error
	client := &acme.Client{
		DirectoryURL: cfg.Url,
	}
	client.Key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	a := &acme.Account{
		Contact: []string{
			"mailto:" + cfg.Email,
		},
	}
	_, err = client.Register(ctx, a, acme.AcceptTOS)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		err = nil
	}

	auth, err := client.Authorize(ctx, cfg.Domain)
	if err != nil {
		return nil, err
	}

	var challenge *acme.Challenge
	for _, c := range auth.Challenges {
		if c.Type == "http-01" {
			challenge = c
		}
	}
	if challenge == nil {
		return nil, ErrHTTPChallengeNotFound
	}

	// Determine the correct path to listen on
	cPath := client.HTTP01ChallengePath(challenge.Token)
	cResponse, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return nil, err
	}

	// Create a server that responds to the request
	mux := http.NewServeMux()
	mux.HandleFunc(cPath, func(w http.ResponseWriter, r *http.Request) {
		b := []byte(cResponse)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	})
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		return nil, err
	}
	defer l.Close()
	go func() {
		http.Serve(l, mux)
	}()

	// Perform the challenge
	_, err = client.Accept(context.TODO(), challenge)
	if err != nil {
		return nil, err
	}

	// Wait for authorization to complete
	_, err = client.WaitAuthorization(context.TODO(), auth.URI)
	if err != nil {
		return nil, err
	}

	// Generate a key for the domain
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create the CSR (certificate signing request)
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: cfg.Domain,
			},
		},
		key,
	)
	if err != nil {
		return nil, err
	}

	ders, _, err := client.CreateCert(context.TODO(), csr, 0, true)
	if err != nil {
		return nil, err
	}

	pemCert := bytes.NewBufferString("")
	for _, der := range ders {
		err := pem.Encode(pemCert, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})
		if err != nil {
			return nil, err
		}
	}

	ecpBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(pemCert.Bytes(), pem.EncodeToMemory(&pem.Block{
		Type: "ECDSA PRIVATE KEY",
		Bytes: ecpBytes,
	}))
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{cert},
	}, nil
}

type ECDSAConfig struct {
	Domain string
}

func ECDSA(cfg ECDSAConfig) (*tls.Config, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	tpl := caCert(cfg.Domain)
	tpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	certDer, err := x509.CreateCertificate(
		rand.Reader,
		tpl,
		tpl,
		privateKey.Public(),
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: certDer,
	}), pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{cert},
	}, nil
}