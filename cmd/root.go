package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/gfyrag/httpproxy/pkg"
	"github.com/Sirupsen/logrus"
	"github.com/gfyrag/httpproxy/pkg/cache"
	"crypto/tls"
	"net"
	"crypto/x509"
	"crypto"
)

var RootCmd = &cobra.Command{
	Use:   "httpproxy",
	Short: "A generic http proxy",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logrus.New()
		if viper.GetBool("debug") {
			logger.Level = logrus.DebugLevel
		}

		var options []httpproxy.Option
		options = append(options, httpproxy.WithLogger(logger))

		var storage cache.Storage
		switch viper.GetString("store") {
		case "memory":
			storage = cache.MemStorage()
		case "dir":
			storage = cache.Dir(viper.GetString("store-path"))
		}
		options = append(options, httpproxy.WithCache(cache.New(cache.WithStorage(storage))))

		if viper.GetBool("tls-intercept") {
			var (
				tlsConfig *tls.Config
				err error
			)
			if viper.GetString("tls-cert") == "" {
				switch viper.GetString("tls-gen-key") {
				case "ecdsa":
					tlsConfig, err = httpproxy.RSA()
				case "rsa":
					tlsConfig, err = httpproxy.ECDSA()
				default:
					logger.Errorf("unexpected tls renegotiation value: %s", viper.GetString("tls-renegotiation"))
					os.Exit(1)
				}
			} else {
				cert, err := tls.LoadX509KeyPair(viper.GetString("tls-cert"), viper.GetString("tls-key"))
				if err != nil {
					logger.Errorf("error loading certificate: %s", err)
					os.Exit(1)
				}


				ca, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					logger.Errorf("error loading certificate: %s", err)
					os.Exit(1)
				}

				tlsConfig, err = httpproxy.ManagedCertPool(cert.PrivateKey.(crypto.Signer), ca)
			}
			if err != nil {
				logger.Error(err)
				os.Exit(1)
			}

			options = append(options, httpproxy.WithTLSConfig(tlsConfig))

			switch viper.GetString("tls-renegotiation") {
			case "none":
			// Do nothing, it is the default
			case "once":
				tlsConfig.Renegotiation = tls.RenegotiateOnceAsClient
			case "free":
				tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
			default:
				logger.Errorf("unexpected tls renegotiation value: %s", viper.GetString("tls-renegotiation"))
				os.Exit(1)
			}

			options = append(options, httpproxy.WithConnectHandler(&httpproxy.TLSBridge{}))
		}

		addr, err := net.ResolveTCPAddr("tcp", viper.GetString("addr"))
		if err != nil {
			logger.Error(err)
			os.Exit(1)
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			logger.Errorf("unable to listen tcp: %s", err)
			os.Exit(1)
		}

		logger.Infoln("Proxy started.")
		proxy := httpproxy.Proxy(l, options...)
		err = proxy.Run()
		if err != nil {
			logger.Error(err)
			os.Exit(1)
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.Flags().Bool("debug", false, "Debug mode")
	RootCmd.Flags().String("store", "memory", "Store type")
	RootCmd.Flags().String("store-path", "/tmp", "Store path for 'dir' store type")
	RootCmd.Flags().String("tls-renegotiation", "none", "Whether or not enable tls renegotiation")
	RootCmd.Flags().Bool("tls-intercept", true, "Intercept ssl connections")
	RootCmd.Flags().String("tls-gen-key", "rsa", "Private key type to generate")
	RootCmd.Flags().String("tls-cert", "", "Path to CA certificate to use")
	RootCmd.Flags().String("tls-key", "", "Path to CA key to use")
	RootCmd.Flags().String("addr", ":3128", "Listening addr")
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
	viper.AutomaticEnv()
}
