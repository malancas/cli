package verification

import (
	"fmt"
	"testing"

	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/test/data"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type MockSigstoreVerifier struct {
	t           *testing.T
	mockResults []*AttestationProcessingResult
}

func (v *MockSigstoreVerifier) Verify(att []*api.Attestation, _ verify.PolicyBuilder) ([]*AttestationProcessingResult, error) {
	if v.mockResults != nil {
		return v.mockResults, nil
	}

	statement := &in_toto.Statement{}
	statement.PredicateType = SLSAPredicateV1

	result := AttestationProcessingResult{
		Attestation: &api.Attestation{
			Bundle: data.SigstoreBundle(v.t),
		},
		VerificationResult: &verify.VerificationResult{
			Statement: statement,
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{
					Extensions: certificate.Extensions{
						BuildSignerURI:           "https://github.com/github/example/.github/workflows/release.yml@refs/heads/main",
						SourceRepositoryOwnerURI: "https://github.com/sigstore",
						SourceRepositoryURI:      "https://github.com/sigstore/sigstore-js",
						Issuer:                   "https://token.actions.githubusercontent.com",
					},
				},
			},
		},
	}

	results := make([]*AttestationProcessingResult, len(att))
	for i := range att {
		results[i] = &result
	}
	return results, nil
}

func NewMockSigstoreVerifier(t *testing.T) *MockSigstoreVerifier {
	result := BuildSigstoreJsMockResult(t)
	results := []*AttestationProcessingResult{&result}

	return &MockSigstoreVerifier{t, results}
}

func NewMockSigstoreVerifierWithMockResults(t *testing.T, mockResults []*AttestationProcessingResult) *MockSigstoreVerifier {
	return &MockSigstoreVerifier{t, mockResults}
}

type FailSigstoreVerifier struct{}

func (v *FailSigstoreVerifier) Verify([]*api.Attestation, verify.PolicyBuilder) ([]*AttestationProcessingResult, error) {
	return nil, fmt.Errorf("failed to verify attestations")
}

func BuildMockResult(b *bundle.Bundle, buildConfigURI, buildSignerURI, sourceRepoOwnerURI, sourceRepoURI, issuer string) AttestationProcessingResult {
	statement := &in_toto.Statement{}
	statement.PredicateType = SLSAPredicateV1

	return AttestationProcessingResult{
		Attestation: &api.Attestation{
			Bundle: b,
		},
		VerificationResult: &verify.VerificationResult{
			Statement: statement,
			Signature: &verify.SignatureVerificationResult{
				Certificate: &certificate.Summary{
					Extensions: certificate.Extensions{
						BuildConfigURI:           buildConfigURI,
						BuildSignerURI:           buildSignerURI,
						Issuer:                   issuer,
						SourceRepositoryOwnerURI: sourceRepoOwnerURI,
						SourceRepositoryURI:      sourceRepoURI,
					},
				},
			},
		},
	}
}

func BuildSigstoreJsMockResult(t *testing.T) AttestationProcessingResult {
	bundle := data.SigstoreBundle(t)
	buildConfigURI := "https://github.com/sigstore/sigstore-js/.github/workflows/build.yml@refs/heads/main"
	buildSignerURI := "https://github.com/github/example/.github/workflows/release.yml@refs/heads/main"
	sourceRepoOwnerURI := "https://github.com/sigstore"
	sourceRepoURI := "https://github.com/sigstore/sigstore-js"
	issuer := "https://token.actions.githubusercontent.com"
	return BuildMockResult(bundle, buildConfigURI, buildSignerURI, sourceRepoOwnerURI, sourceRepoURI, issuer)
}

type MockSignedEntityVerifier struct{}

func (v *MockSignedEntityVerifier) Verify(entity verify.SignedEntity, pb verify.PolicyBuilder) (*verify.VerificationResult, error) {
	return &verify.VerificationResult{
		MediaType: "dfsdfsd",
	}, nil
}

type failAfterNCallsVerifier struct {
	failAfterNCalls int
	numCalls        int
}

func (v *failAfterNCallsVerifier) Verify(entity verify.SignedEntity, pb verify.PolicyBuilder) (*verify.VerificationResult, error) {
	if v.failAfterNCalls == v.numCalls {
		return nil, fmt.Errorf("sigstore verification failed")
	}
	v.numCalls++
	return &verify.VerificationResult{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
	}, nil
}

type FailSignedEntityVerifier struct{}

func (v *FailSignedEntityVerifier) Verify(entity verify.SignedEntity, pb verify.PolicyBuilder) (*verify.VerificationResult, error) {
	return nil, fmt.Errorf("failed to verify signed entity")
}

func newVerifierWithMockEntityVerifier() *LiveSigstoreVerifier {
	verifier := NewLiveSigstoreVerifier(SigstoreConfig{
		Logger: io.NewTestHandler(),
	})
	verifier.ChooseVerifier = func(issuer string) (SignedEntityVerifier, error) {
		return &MockSignedEntityVerifier{}, nil
	}
	return verifier
}

func newVerifierWithFailEntityVerifier() *LiveSigstoreVerifier {
	verifier := NewLiveSigstoreVerifier(SigstoreConfig{
		Logger: io.NewTestHandler(),
	})
	verifier.ChooseVerifier = func(issuer string) (SignedEntityVerifier, error) {
		return &FailSignedEntityVerifier{}, nil
	}
	return verifier
}

func newVerifierWithFailAfterNCallsVerifier(failAfterNCalls int) *LiveSigstoreVerifier {
	verifier := NewLiveSigstoreVerifier(SigstoreConfig{
		Logger: io.NewTestHandler(),
	})

	failVerifier := &failAfterNCallsVerifier{
		failAfterNCalls: failAfterNCalls,
	}
	verifier.ChooseVerifier = func(issuer string) (SignedEntityVerifier, error) {
		return failVerifier, nil
	}
	return verifier
}
