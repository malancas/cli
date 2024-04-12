package verify

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact/oci"
	"github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/verification"

	"github.com/cli/cli/v2/pkg/httpmock"
	"github.com/stretchr/testify/require"
)

func newTestClient(reg *httpmock.Registry) *api.LiveClient {
	client := &http.Client{}
	httpmock.ReplaceTripper(client, reg)
	return api.NewLiveClient(client, io.NewTestHandler())
}

func TestRunVerify_API(t *testing.T) {
	logger := io.NewTestHandler()

	publicGoodOpts := Options{
		ArtifactPath:     artifactPath,
		BundlePath:       bundlePath,
		DigestAlgorithm:  "sha512",
		APIClient:        api.NewTestClient(),
		Logger:           logger,
		OCIClient:        oci.MockClient{},
		OIDCIssuer:       GitHubOIDCIssuer,
		Owner:            "sigstore",
		SANRegex:         "^https://github.com/sigstore/",
		SigstoreVerifier: verification.NewMockSigstoreVerifier(t),
	}

	t.Run("failing GitHub API request", func(t *testing.T) {
		opts := publicGoodOpts

		artifact, err := artifact.NewDigestedArtifact(opts.OCIClient, opts.ArtifactPath, opts.DigestAlgorithm)
		require.NoError(t, err)

		hm := &httpmock.Registry{}

		path := "api/v3/sigstore/sigstore-js/attestations/%s"
		fullPath := fmt.Sprintf(path, artifact.DigestWithAlg())

		hm.Register(
			httpmock.REST("GET", fullPath),
			httpmock.StatusStringResponse(http.StatusOK, `{"attestations": [{"bundle": "test"}]}`),
		)

		/*
			vars := map[string]interface{}{"name": "Mona"}
			response := struct {
				Viewer struct {
					Login string
				}
			}{}

			err := client.GraphQL("github.com", "QUERY", vars, &response)
			assert.NoError(t, err)
			assert.Equal(t, "hubot", response.Viewer.Login)
		*/

		opts.APIClient = newTestClient(http)
		err = runVerify(&opts)
		require.Error(t, err)
	})
}
