package verify

import (
	"fmt"

	"github.com/cli/cli/v2/internal/ghinstance"
	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact/oci"
	"github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/verification"
	"github.com/cli/cli/v2/pkg/cmdutil"
	ghauth "github.com/cli/go-gh/v2/pkg/auth"
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

	// Prepare for tenancy if detected
	if ghauth.IsTenancy(hostname) {
		td, err := apiClient.GetTrustDomain()
		if err != nil {
			return nil, fmt.Errorf("error getting trust domain, make sure you are authenticated against the host: %w", err)
		}

		tenant, found := ghinstance.TenantName(hostname)
		if !found {
			return nil, fmt.Errorf("invalid hostname provided: '%s'",
				hostname)
		}
		sigstoreConfig.TrustDomain = td
		opts.Tenant = tenant
	}

	sigstoreVerifier := verification.NewLiveSigstoreVerifier(sigstoreConfig)

	return &Config{
		APIClient:        apiClient,
		OCIClient:        oci.NewLiveClient(),
		SigstoreVerifier: sigstoreVerifier,
	}, nil
}
