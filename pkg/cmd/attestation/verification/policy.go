package verification

import (
	"encoding/hex"
	"fmt"

	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// represents the GitHub hosted runner in the certificate RunnerEnvironment extension
const GitHubRunner = "github-hosted"

// BuildDigestPolicyOption builds a verify.ArtifactPolicyOption
// from the given artifact digest and digest algorithm
func BuildDigestPolicyOption(a artifact.DigestedArtifact) (verify.ArtifactPolicyOption, error) {
	// sigstore-go expects the artifact digest to be decoded from hex
	decoded, err := hex.DecodeString(a.Digest())
	if err != nil {
		return nil, err
	}
	return verify.WithArtifactDigest(a.Algorithm(), decoded), nil
}

type EnforcementCriteria struct {
	Certificate   certificate.Summary
	PredicateType string
	SANRegex      string
	SAN           string
}

func (c EnforcementCriteria) Valid() error {
	if c.Certificate.Issuer == "" {
		return fmt.Errorf("Issuer must be set")
	}
	if c.Certificate.RunnerEnvironment != "" && c.Certificate.RunnerEnvironment != GitHubRunner {
		return fmt.Errorf("RunnerEnvironment must be set to either \"\" or %s", GitHubRunner)
	}
	if c.Certificate.SourceRepositoryOwnerURI == "" {
		return fmt.Errorf("SourceRepositoryOwnerURI must be set")
	}
	if c.PredicateType == "" {
		return fmt.Errorf("PredicateType must be set")
	}
	if c.SANRegex == "" && c.SAN == "" {
		return fmt.Errorf("SANRegex or SAN must be set")
	}
	return nil
}
