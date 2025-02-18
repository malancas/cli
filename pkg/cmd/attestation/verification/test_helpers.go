package verification

import (
	"testing"

	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact"
	"github.com/cli/cli/v2/pkg/cmd/attestation/test"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
)

func PublicGoodPolicy(t *testing.T) verify.PolicyBuilder {
	t.Helper()

	artifactPath := test.NormalizeRelativePath("../test/data/sigstore-js-2.1.0.tgz")
	publicGoodArtifact, err := artifact.NewDigestedArtifact(nil, artifactPath, "sha512")
	require.NoError(t, err)

	return BuildPolicy(t, *publicGoodArtifact)
}

func BuildPolicy(t *testing.T, artifact artifact.DigestedArtifact) verify.PolicyBuilder {
	t.Helper()

	artifactDigestPolicyOption, err := BuildDigestPolicyOption(artifact)
	require.NoError(t, err)

	return verify.NewPolicy(artifactDigestPolicyOption, verify.WithoutIdentitiesUnsafe())
}

func GetAttestationsFor(t *testing.T, bundlePath string) []*api.Attestation {
	t.Helper()

	attestations, err := GetLocalAttestations(bundlePath)
	require.NoError(t, err)

	return attestations
}
