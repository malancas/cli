package verification

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

var (
	GitHubOIDCIssuer       = "https://token.actions.githubusercontent.com"
	GitHubTenantOIDCIssuer = "https://token.actions.%s.ghe.com"
)

func VerifyCertExtensions(results []*AttestationProcessingResult, ec EnforcementCriteria) error {
	if len(results) == 0 {
		return errors.New("no attestations proccessing results")
	}

	var lastErr error
	for _, attestation := range results {
		err := verifyCertExtensions(*attestation.VerificationResult.Signature.Certificate, ec)
		if err == nil {
			// if at least one attestation is verified, we're good as verification
			// is defined as successful if at least one attestation is verified
			return nil
		}
		lastErr = err
	}

	// if we have exited the for loop without returning early due to successful
	// verification, we need to return an error
	return lastErr
}

func verifyCertExtensions(verifiedCert certificate.Summary, criteria EnforcementCriteria) error {
	sourceRepositoryOwnerURI := verifiedCert.Extensions.SourceRepositoryOwnerURI
	if !strings.EqualFold(criteria.Certificate.SourceRepositoryOwnerURI, sourceRepositoryOwnerURI) {
		return fmt.Errorf("expected SourceRepositoryOwnerURI to be %s, got %s", criteria.Certificate.SourceRepositoryOwnerURI, sourceRepositoryOwnerURI)
	}

	// if repo is set, check the SourceRepositoryURI field
	if criteria.Certificate.SourceRepositoryURI != "" {
		sourceRepositoryURI := verifiedCert.Extensions.SourceRepositoryURI
		if !strings.EqualFold(criteria.Certificate.SourceRepositoryURI, sourceRepositoryURI) {
			return fmt.Errorf("expected SourceRepositoryURI to be %s, got %s", criteria.Certificate.SourceRepositoryURI, sourceRepositoryURI)
		}
	}

	// if issuer is anything other than the default, use the user-provided value;
	// otherwise, select the appropriate default based on the tenant
	certIssuer := verifiedCert.Extensions.Issuer
	if !strings.EqualFold(criteria.Certificate.Issuer, certIssuer) {
		if strings.Index(certIssuer, criteria.Certificate.Issuer+"/") == 0 {
			return fmt.Errorf("expected Issuer to be %s, got %s -- if you have a custom OIDC issuer policy for your enterprise, use the --cert-oidc-issuer flag with your expected issuer", criteria.Certificate.Issuer, certIssuer)
		}
		return fmt.Errorf("expected Issuer to be %s, got %s", criteria.Certificate.Issuer, certIssuer)
	}

	return nil
}
