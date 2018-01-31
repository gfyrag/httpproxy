package httpproxy

import (
	"crypto/tls"
	"fmt"
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
)

var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for localhostCert.
var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)

func DefaultTLSConfig() *tls.Config {
	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		panic(fmt.Sprintf("creating default tls config: %v", err))
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	certpool := x509.NewCertPool()
	certpool.AddCert(x509Cert)

	return &tls.Config{
		RootCAs: certpool,
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{cert},
	}
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