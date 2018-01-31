package httpproxy

import (
	"github.com/stretchr/testify/suite"
	"testing"
	"context"
)


type TLSTestSuite struct {
	suite.Suite
}

func (s *TLSTestSuite) TestHTTP() {

	cfg, err := ACME(context.Background(), ACMEConfig{
		Domain: "gfyrag.me",
		Email: "geoffrey.ragot@gmail.com",
		Url: "https://acme-staging.api.letsencrypt.org/directory",
	})
	s.NoError(err)
	s.NotNil(cfg)
}


func TestTLS(t *testing.T) {
	suite.Run(t, &TLSTestSuite{})
}
