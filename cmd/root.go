package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/gfyrag/httpproxy/pkg"
	"net/http"
	"github.com/Sirupsen/logrus"
)

var RootCmd = &cobra.Command{
	Use:   "httpproxy",
	Short: "A generic http proxy",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logrus.New()
		if viper.GetBool("debug") {
			logger.Level = logrus.DebugLevel
		}

		var store httpproxy.CacheStorage
		switch viper.GetString("store") {
		case "memory":
			// Default
		case "dir":
			store = httpproxy.Dir(viper.GetString("store-path"))
		}

		logger.Infoln("Proxy started.")
		http.ListenAndServe(":3128", &httpproxy.Proxy{
			ConnectHandler: &httpproxy.SSLBump{
				Config: httpproxy.DefaultTLSConfig(),
			},
			Logger: logger,
			Cache: &httpproxy.Cache{
				Storage: store,
			},
			BufferSize: viper.GetInt("buffer-size"),
		})
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
	RootCmd.Flags().Int("buffer-size", 1024, "Internal buffer size for requests")
	RootCmd.Flags().String("store", "memory", "Store type")
	RootCmd.Flags().String("store-path", "/tmp", "Store path for 'dir' store type")
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
	viper.AutomaticEnv()
}
