//go:build integration

package verification

import (
	"testing"

	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact"
	"github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/test"

	"github.com/stretchr/testify/require"
)

func TestLiveSigstoreVerifier(t *testing.T) {
	type testcase struct {
		name         string
		attestations []*api.Attestation
		expectErr    bool
		errContains  string
	}

	testcases := []testcase{
		{
			name:         "with invalid signature",
			attestations: GetAttestationsFor(t, "../test/data/sigstoreBundle-invalid-signature.json"),
			expectErr:    true,
			errContains:  "verifying with issuer \"sigstore.dev\"",
		},
		{
			name:         "with valid artifact and JSON lines file containing multiple Sigstore bundles",
			attestations: GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl"),
		},
		{
			name:         "with invalid bundle version",
			attestations: GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json"),
			expectErr:    true,
			errContains:  "unsupported bundle version",
		},
		{
			name:         "with no attestations",
			attestations: []*api.Attestation{},
			expectErr:    true,
			errContains:  "no attestations were verified",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := NewLiveSigstoreVerifier(SigstoreConfig{
				Logger: io.NewTestHandler(),
			})

			results, err := verifier.Verify(tc.attestations, PublicGoodPolicy(t))

			if tc.expectErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.errContains)
				require.Nil(t, results)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.attestations), len(results))
			}
		})
	}

	t.Run("with 2/3 verified attestations", func(t *testing.T) {
		verifier := NewLiveSigstoreVerifier(SigstoreConfig{
			Logger: io.NewTestHandler(),
		})

		invalidBundle := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json")
		attestations := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		attestations = append(attestations, invalidBundle[0])
		require.Len(t, attestations, 3)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))

		require.Len(t, results, 2)
		require.NoError(t, err)
	})

	t.Run("fail with 0/2 verified attestations", func(t *testing.T) {
		verifier := NewLiveSigstoreVerifier(SigstoreConfig{
			Logger: io.NewTestHandler(),
		})

		invalidBundle := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json")
		attestations := GetAttestationsFor(t, "../test/data/sigstoreBundle-invalid-signature.json")
		attestations = append(attestations, invalidBundle[0])
		require.Len(t, attestations, 2)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		require.Nil(t, results)
		require.Error(t, err)
	})

	t.Run("with GitHub Sigstore artifact", func(t *testing.T) {
		githubArtifactPath := test.NormalizeRelativePath("../test/data/github_provenance_demo-0.0.12-py3-none-any.whl")
		githubArtifact, err := artifact.NewDigestedArtifact(nil, githubArtifactPath, "sha256")
		require.NoError(t, err)

		githubPolicy := BuildPolicy(t, *githubArtifact)

		attestations := GetAttestationsFor(t, "../test/data/github_provenance_demo-0.0.12-py3-none-any-bundle.jsonl")

		verifier := NewLiveSigstoreVerifier(SigstoreConfig{
			Logger: io.NewTestHandler(),
		})

		results, err := verifier.Verify(attestations, githubPolicy)
		require.Len(t, results, 1)
		require.NoError(t, err)
	})

	t.Run("with custom trusted root", func(t *testing.T) {
		attestations := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")

		verifier := NewLiveSigstoreVerifier(SigstoreConfig{
			Logger:      io.NewTestHandler(),
			TrustedRoot: test.NormalizeRelativePath("../test/data/trusted_root.json"),
		})

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		require.Len(t, results, 2)
		require.NoError(t, err)
	})
}
