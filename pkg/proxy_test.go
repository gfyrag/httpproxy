package httpproxy

import (
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"strings"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"os/exec"
	"os"
	"net"
	"fmt"
	"time"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestSecuredWebSocket(t *testing.T) {

	ws := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			panic(err)
		}
		conn.Close()
	})
	tlsConfig, err := RSA()
	assert.NoError(t, err)
	l := MustListenRandom()
	defer l.Close()
	proxy := Proxy(l, WithTLSConfig(tlsConfig), WithConnectHandler(&TLSBridge{}))
	go proxy.Run()
	wssBackend := httptest.NewTLSServer(ws)

	dialer := websocket.Dialer{
		Proxy: func(*http.Request) (*url.URL, error) {
			return proxy.Url(), nil
		},
		TLSClientConfig: &tls.Config{
			RootCAs: wssBackend.TLS.RootCAs,
			InsecureSkipVerify: true,
		},
	}

	_, _, err = dialer.Dial(strings.Replace(wssBackend.URL, "http", "ws", -1), nil)
	assert.NoError(t, err)
}

// https://www.karlrupp.net/en/computer/nat_tutorial
// https://connect.ed-diamond.com/GNU-Linux-Magazine/GLMFHS-041/Introduction-a-Netfilter-et-iptables
func TestProxy(t *testing.T) {

	// To avoid infinite recursion with iptables, we choose a network interface which is not "lo"
	// for client connections
	interfaces, err := net.Interfaces()
	assert.NoError(t, err)
	var i net.Interface
	for _, ii := range interfaces {
		if ii.Name != "lo" {
			i = ii
			break
		}
	}
	addrs, err := i.Addrs()
	addr := addrs[0]

	suites := []struct {
		Name string
		Backend        *httptest.Server
		ExpectedStatus int
		Url            string
		Client         *http.Client
		Transparent    bool
		Options        []Option
	} {
		{
			Name: "http backend with explicit proxy",
			Backend: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			ExpectedStatus: 200,
		},
		{
			Name: "http backend with transparent proxy",
			Backend: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			ExpectedStatus: 200,
			Options: []Option {
				WithDialer(&net.Dialer{
					Timeout: 5*time.Second,
					LocalAddr: &net.TCPAddr{
						IP: addr.(*net.IPNet).IP,
					},
				}),
			},
			Transparent: true,
		},
		{
			Name: "https backend with transparent proxy",
			Backend: httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			ExpectedStatus: 200,
			Transparent: true,
			Options: []Option {
				WithDialer(&net.Dialer{
					Timeout: 5*time.Second,
					LocalAddr: &net.TCPAddr{
						IP: addr.(*net.IPNet).IP,
					},
				}),
				WithTLSConfig(MustRSA()),
			},
		},
		{
			Name: "no backend with explicit proxy",
			ExpectedStatus: 503,
			Url: "http://127.0.0.1:1234",
		},
		{
			Name: "https backend (with rsa connect handler) with explicit proxy",
			Backend: httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			ExpectedStatus: 200,
			Options: []Option {
				WithTLSConfig(MustRSA()),
				WithConnectHandler(&TLSBridge{}),
			},
		},
		{
			Name: "https backend (with passthrough connect handler) with explicit proxy",
			Backend: httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
			ExpectedStatus: 200,
		},
	}

	for _, suite := range suites {
		t.Run(suite.Name, func(t *testing.T) {

			l := MustListenRandom()
			defer l.Close()

			port := fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)

			proxy := Proxy(l, suite.Options...)
			go proxy.Run()

			var (
				u *url.URL
				err error
				client *http.Client
			)
			if suite.Backend != nil {
				u, err = u.Parse(suite.Backend.URL)
				client = suite.Backend.Client()
			} else {
				u, err = u.Parse(suite.Url)
				if suite.Client == nil {
					client = http.DefaultClient
				} else {
					client = suite.Client
				}
			}
			assert.NoError(t, err)

			if client.Transport == nil {
				client.Transport = &http.Transport{}
			}

			if client.Transport.(*http.Transport).TLSClientConfig == nil {
				client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{}
			}

			client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

			// Spawn iptables
			if suite.Transparent {
				cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "!", "--source", addr.String(), "--dport", u.Port(), "-j", "REDIRECT", "--to-port", port)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				assert.NoError(t, cmd.Run())

				defer func() {
					cmd := exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "!", "--source", addr.String(), "--dport", u.Port(), "-j", "REDIRECT", "--to-port", port)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					assert.NoError(t, cmd.Run())
				}()
			} else {
				client.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
					return proxy.Url(), nil
				}
			}

			rsp, err := client.Get(u.String())
			assert.NoError(t, err)
			if rsp != nil {
				assert.Equal(t, suite.ExpectedStatus, rsp.StatusCode)
			}
		})
	}
}