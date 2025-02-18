package verification

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		assert.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("with 1/2 verified attestations - sigstore verification failed", func(t *testing.T) {
		verifier := newVerifierWithFailAfterNCallsVerifier(1)

		attestations := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		require.Len(t, attestations, 2)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		assert.NoError(t, err)
		assert.Len(t, results, 1)
	})

	t.Run("fail with 0/2 verified attestations", func(t *testing.T) {
		verifier := newVerifierWithFailEntityVerifier()

		attestations := GetAttestationsFor(t, "../test/data/sigstore-js-2.1.0_with_2_bundles.jsonl")
		require.Len(t, attestations, 2)

		results, err := verifier.Verify(attestations, PublicGoodPolicy(t))
		assert.Error(t, err)
		assert.Nil(t, results)
	})
}
