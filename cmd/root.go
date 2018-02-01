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
		logger.Infoln("Proxy started.")
		http.ListenAndServe(":3128", &httpproxy.Proxy{
			ConnectHandler: &httpproxy.SSLBump{
				Config: httpproxy.DefaultTLSConfig(),
			},
			Logger: logger,
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
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
	viper.AutomaticEnv()
}
