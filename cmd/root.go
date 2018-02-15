package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/gfyrag/httpproxy/pkg"
	"net/http"
	"github.com/Sirupsen/logrus"
	"github.com/gfyrag/httpproxy/pkg/cache"
	"crypto/tls"
)

var RootCmd = &cobra.Command{
	Use:   "httpproxy",
	Short: "A generic http proxy",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logrus.New()
		if viper.GetBool("debug") {
			logger.Level = logrus.DebugLevel
		}

		var storage cache.Storage
		switch viper.GetString("store") {
		case "memory":
			storage = cache.MemStorage()
		case "dir":
			storage = cache.Dir(viper.GetString("store-path"))
		}

		tlsConfig, err := httpproxy.RSA(httpproxy.RSAConfig{
			Domain: viper.GetString("domain"),
		})
		if err != nil {
			logger.Error(err)
			os.Exit(1)
		}

		switch viper.GetString("tls-renegotiation") {
		case "none":
			// Do nothing, it is the default
		case "once":
			tlsConfig.Renegotiation = tls.RenegotiateOnceAsClient
		case "free":
			tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
		default:
			logger.Errorf("unexpected tls renegotiation value: %s", viper.GetString("tls-renegotiation"))
		}

		logger.Infoln("Proxy started.")
		err = http.ListenAndServe(fmt.Sprintf(":%d", viper.GetInt("port")), httpproxy.Proxy(
			httpproxy.WithConnectHandler(&httpproxy.SSLBump{
				Config: tlsConfig,
			}),
			httpproxy.WithLogger(logger),
			httpproxy.WithCache(cache.New(cache.WithStorage(storage))),
		))
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
	RootCmd.Flags().String("domain", "", "Common name for generated certificates")
	RootCmd.Flags().String("store", "memory", "Store type")
	RootCmd.Flags().String("store-path", "/tmp", "Store path for 'dir' store type")
	RootCmd.Flags().String("tls-renegotiation", "none", "Whether or not enable tls renegotiation")
	RootCmd.Flags().Int("port", 3128, "Http port")
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
	viper.AutomaticEnv()
}
