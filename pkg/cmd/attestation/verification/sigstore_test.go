//go:build integration

package verification

import (
	"testing"

	"github.com/cli/cli/v2/pkg/cmd/attestation/api"

	"github.com/stretchr/testify/require"
)

func TestSigstoreVerifier(t *testing.T) {
	type testcase struct {
		name         string
		attestations []*api.Attestation
		expectErr    bool
		errContains  string
	}

	testcases := []testcase{
		{
			name:         "with invalid signature",
			attestations: getAttestationsFor(t, "../test/data/sigstoreBundle-invalid-signature.json"),
			expectErr:    true,
			errContains:  "verifying with issuer \"sigstore.dev\"",
		},
		{
			name:         "with valid artifact and JSON lines file containing multiple Sigstore bundles",
			attestations: getAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl"),
		},
		{
			name:         "with invalid bundle version",
			attestations: getAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json"),
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
			verifier := NewMockSigstoreVerifier(t)

			results, err := verifier.Verify(tc.attestations, publicGoodPolicy(t))

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
		verifier := NewMockSigstoreVerifier(t)

		invalidBundle := getAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json")
		attestations := getAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		attestations = append(attestations, invalidBundle[0])
		require.Len(t, attestations, 3)

		results, err := verifier.Verify(attestations, publicGoodPolicy(t))

		require.Len(t, results, 2)
		require.NoError(t, err)
	})

	t.Run("fail with 0/2 verified attestations", func(t *testing.T) {
		verifier := NewMockSigstoreVerifier(t)

		invalidBundle := getAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json")
		attestations := getAttestationsFor(t, "../test/data/sigstoreBundle-invalid-signature.json")
		attestations = append(attestations, invalidBundle[0])
		require.Len(t, attestations, 2)

		results, err := verifier.Verify(attestations, publicGoodPolicy(t))
		require.Nil(t, results)
		require.Error(t, err)
	})
}
