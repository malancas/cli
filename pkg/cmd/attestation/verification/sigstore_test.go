package verification

import (
	"testing"

	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/stretchr/testify/require"
)

func TestSigstoreVerifier(t *testing.T) {
	t.Run("with 2/3 verified attestations - unsupported bundle version", func(t *testing.T) {
		verifier := newVerifierWithMockEntityVerifier()

		invalidBundle := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0-bundle-v0.1.json")
		attestations := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		attestations = append(attestations, invalidBundle[0])
		require.Len(t, attestations, 3)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		require.NoError(t, err)
		require.Len(t, results, 2)
	})

	t.Run("with 2/3 verified attestations - sigstore verification failed", func(t *testing.T) {
		verifier := newVerifierWithFailAfterNCallsVerifier(2)

		bundles := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		attestations := []*api.Attestation{bundles[0], bundles[1], bundles[0]}
		require.Len(t, attestations, 3)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		require.NoError(t, err)
		require.Len(t, results, 2)
	})

	t.Run("fail with 0/2 verified attestations", func(t *testing.T) {
		verifier := newVerifierWithFailEntityVerifier()

		attestations := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		require.Len(t, attestations, 2)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		require.Error(t, err)
		require.Nil(t, results)
	})
}
