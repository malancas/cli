package verify

import (
	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact/oci"
	"github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/verification"
	"github.com/cli/cli/v2/pkg/cmdutil"
)

// Config captures the configuration for the verify command
type Config struct {
	APIClient        api.Client
	OCIClient        oci.Client
	SigstoreVerifier verification.SigstoreVerifier
}

func newConfig(f *cmdutil.Factory, hostname string, trustedRoot string, noPublicGood bool, logger *io.Handler) (*Config, error) {
	hc, err := f.HttpClient()
	if err != nil {
		return nil, err
	}
	apiClient := api.NewLiveClient(hc, hostname, logger)

	sigstoreConfig := verification.SigstoreConfig{
		TrustedRoot:  trustedRoot,
		Logger:       logger,
		NoPublicGood: noPublicGood,
	}
	sigstoreVerifier := verification.NewLiveSigstoreVerifier(sigstoreConfig)

	return &Config{
		APIClient:        apiClient,
		OCIClient:        oci.NewLiveClient(),
		SigstoreVerifier: sigstoreVerifier,
	}, nil
}
