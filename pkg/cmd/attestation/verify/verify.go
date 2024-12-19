package verify

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cli/cli/v2/internal/ghinstance"
	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact/oci"
	"github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/verification"
	"github.com/cli/cli/v2/pkg/cmdutil"
	ghauth "github.com/cli/go-gh/v2/pkg/auth"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewVerifyCmd(f *cmdutil.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{}
	verifyCmd := &cobra.Command{
		Use:   "verify [<file-path> | oci://<image-uri>] [--owner | --repo]",
		Args:  cmdutil.ExactArgs(1, "must specify file path or container image URI, as well as one of --owner or --repo"),
		Short: "Verify an artifact's integrity using attestations",
		Long: heredoc.Docf(`
			Verify the integrity and provenance of an artifact using its associated
			cryptographically signed attestations.

			In order to verify an attestation, you must validate the identity of the Actions
			workflow that produced the attestation (a.k.a. the signer workflow). Given this
			identity, the verification process checks the signatures in the attestations,
			and confirms that the attestation refers to provided artifact.

			To specify the artifact, the command requires:
			* a file path to an artifact, or
			* a container image URI (e.g. %[1]soci://<image-uri>%[1]s)
			  * (note that if you provide an OCI URL, you must already be authenticated with
			its container registry)

			To fetch the attestation, and validate the identity of the signer, the command
			requires either:
			* the %[1]s--repo%[1]s flag (e.g. --repo github/example).
			* the %[1]s--owner%[1]s flag (e.g. --owner github), or

			The %[1]s--repo%[1]s flag value must match the name of the GitHub repository
			that the artifact is linked with.

			The %[1]s--owner%[1]s flag value must match the name of the GitHub organization
			that the artifact's linked repository belongs to.

			By default, the verify command will:
			- only verify provenance attestations
			- attempt to fetch relevant attestations via the GitHub API.

			To verify other types of attestations, use the %[1]s--predicate-type%[1]s flag.

			To use your artifact's OCI registry instead of GitHub's API, use the
			%[1]s--bundle-from-oci%[1]s flag. For offline verification, using attestations
			stored on desk (c.f. the download command), provide a path to the %[1]s--bundle%[1]s flag.

			To see the full results that are generated upon successful verification, i.e.
			for use with a policy engine, provide the %[1]s--format=json%[1]s flag.

			The signer workflow's identity is validated against the Subject Alternative Name (SAN)
			within the attestation certificate. Often, the signer workflow is the
			same workflow that started the run and generated the attestation, and will be
			located inside your repository. For this reason, by default this command uses
			either the %[1]s--repo%[1]s or the %[1]s--owner%[1]s flag value to validate the SAN.

			However, sometimes the caller workflow is not the same workflow that
			performed the signing. If your attestation was generated via a reusable
			workflow, then that reusable workflow is the signer whose identity needs to be
			validated. In this situation, the signer workflow may or may not be located
			inside your %[1]s--repo%[1]s or %[1]s--owner%[1]s.

			When using reusable workflows, use the %[1]s--signer-repo%[1]s, %[1]s--signer-workflow%[1]s,
			or %[1]s--cert-identity%[1]s flags to validate the signer workflow's identity.

			For more policy verification options, see the other available flags.
			`, "`"),
		Example: heredoc.Doc(`
			# Verify an artifact linked with a repository
			$ gh attestation verify example.bin --repo github/example

			# Verify an artifact linked with an organization
			$ gh attestation verify example.bin --owner github

			# Verify an artifact and output the full verification result
			$ gh attestation verify example.bin --owner github --format json

			# Verify an OCI image using attestations stored on disk
			$ gh attestation verify oci://<image-uri> --owner github --bundle sha256:foo.jsonl

			# Verify an artifact signed with a reusable workflow
			$ gh attestation verify example.bin --owner github --signer-repo actions/example
		`),
		// PreRunE is used to validate flags before the command is run
		// If an error is returned, its message will be printed to the terminal
		// along with information about how use the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// set the artifact path
			opts.ArtifactPath = args[0]

			// Check that the given flag combination is valid
			if err := opts.AreFlagsValid(); err != nil {
				return err
			}

			// Clean file path options
			opts.Clean()

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create a logger for use throughout the verify command
			logger := io.NewHandler(f.IOStreams)

			apiClient, err := newAPIClient(f, opts.Hostname, logger)
			if err != nil {
				return err
			}

			sigstoreVerifier := &verification.LiveSigstoreVerifier{
				Logger:       logger,
				TrustedRoot:  opts.TrustedRoot,
				NoPublicGood: opts.NoPublicGood,
			}

			// Prepare for tenancy if detected
			if ghauth.IsTenancy(opts.Hostname) {
				trustDomain, tenant, err := configureTenancy(apiClient, opts.Hostname)
				if err != nil {
					return fmt.Errorf("error getting trust domain, make sure you are authenticated against the host: %w", err)
				}
				sigstoreVerifier.TrustDomain = trustDomain
				opts.Tenant = tenant
			}

			// runF is only used for testing
			if runF != nil {
				return runF(opts)
			}

			if err := runVerify(opts, logger, apiClient, oci.NewLiveClient(), sigstoreVerifier); err != nil {
				return fmt.Errorf("\nError: %v", err)
			}
			return nil
		},
	}

	// general flags
	verifyCmd.Flags().StringVarP(&opts.BundlePath, "bundle", "b", "", "Path to bundle on disk, either a single bundle in a JSON file or a JSON lines file with multiple bundles")
	cmdutil.DisableAuthCheckFlag(verifyCmd.Flags().Lookup("bundle"))
	verifyCmd.Flags().BoolVarP(&opts.UseBundleFromRegistry, "bundle-from-oci", "", false, "When verifying an OCI image, fetch the attestation bundle from the OCI registry instead of from GitHub")
	cmdutil.StringEnumFlag(verifyCmd, &opts.DigestAlgorithm, "digest-alg", "d", "sha256", []string{"sha256", "sha512"}, "The algorithm used to compute a digest of the artifact")
	verifyCmd.Flags().StringVarP(&opts.Owner, "owner", "o", "", "GitHub organization to scope attestation lookup by")
	verifyCmd.Flags().StringVarP(&opts.Repo, "repo", "R", "", "Repository name in the format <owner>/<repo>")
	verifyCmd.MarkFlagsMutuallyExclusive("owner", "repo")
	verifyCmd.MarkFlagsOneRequired("owner", "repo")
	verifyCmd.Flags().StringVarP(&opts.PredicateType, "predicate-type", "", verification.SLSAPredicateV1, "Filter attestations by provided predicate type")
	verifyCmd.Flags().BoolVarP(&opts.NoPublicGood, "no-public-good", "", false, "Do not verify attestations signed with Sigstore public good instance")
	verifyCmd.Flags().StringVarP(&opts.TrustedRoot, "custom-trusted-root", "", "", "Path to a trusted_root.jsonl file; likely for offline verification")
	verifyCmd.Flags().IntVarP(&opts.Limit, "limit", "L", api.DefaultLimit, "Maximum number of attestations to fetch")
	cmdutil.AddFormatFlags(verifyCmd, &opts.exporter)
	// policy enforcement flags
	verifyCmd.Flags().BoolVarP(&opts.DenySelfHostedRunner, "deny-self-hosted-runners", "", false, "Fail verification for attestations generated on self-hosted runners")
	verifyCmd.Flags().StringVarP(&opts.SAN, "cert-identity", "", "", "Enforce that the certificate's subject alternative name matches the provided value exactly")
	verifyCmd.Flags().StringVarP(&opts.SANRegex, "cert-identity-regex", "i", "", "Enforce that the certificate's subject alternative name matches the provided regex")
	verifyCmd.Flags().StringVarP(&opts.SignerRepo, "signer-repo", "", "", "Repository of reusable workflow that signed attestation in the format <owner>/<repo>")
	verifyCmd.Flags().StringVarP(&opts.SignerWorkflow, "signer-workflow", "", "", "Workflow that signed attestation in the format [host/]<owner>/<repo>/<path>/<to>/<workflow>")
	verifyCmd.MarkFlagsMutuallyExclusive("cert-identity", "cert-identity-regex", "signer-repo", "signer-workflow")
	verifyCmd.Flags().StringVarP(&opts.OIDCIssuer, "cert-oidc-issuer", "", verification.GitHubOIDCIssuer, "Issuer of the OIDC token")
	// Set the default gh hostname as the option's default value
	hostname, _ := ghauth.DefaultHost()
	verifyCmd.Flags().StringVarP(&opts.Hostname, "hostname", "", hostname, "Configure host to use")

	return verifyCmd
}

func runVerify(opts *Options, logger *io.Handler, apiClient api.Client, ociClient oci.Client, sgVerifier verification.SigstoreVerifier) error {
	ec, err := newEnforcementCriteria(opts)
	if err != nil {
		logger.Println(logger.ColorScheme.Red("✗ Failed to build verification policy"))
		return err
	}

	if err := ec.Valid(); err != nil {
		logger.Println(logger.ColorScheme.Red("✗ Invalid verification policy"))
		return err
	}

	artifact, err := artifact.NewDigestedArtifact(ociClient, opts.ArtifactPath, opts.DigestAlgorithm)
	if err != nil {
		logger.Printf(logger.ColorScheme.Red("✗ Loading digest for %s failed\n"), opts.ArtifactPath)
		return err
	}

	logger.Printf("Loaded digest %s for %s\n", artifact.DigestWithAlg(), artifact.URL)

	attestations, logMsg, err := getAttestations(opts, *artifact, ociClient, apiClient)
	if err != nil {
		if ok := errors.Is(err, api.ErrNoAttestations{}); ok {
			logger.Printf(logger.ColorScheme.Red("✗ No attestations found for subject %s\n"), artifact.DigestWithAlg())
			return err
		}
		// Print the message signifying failure fetching attestations
		logger.Println(logger.ColorScheme.Red(logMsg))
		return err
	}
	// Print the message signifying success fetching attestations
	logger.Println(logMsg)

	// Apply predicate type filter to returned attestations
	filteredAttestations := verification.FilterAttestations(ec.PredicateType, attestations)
	if len(filteredAttestations) == 0 {
		logger.Printf(logger.ColorScheme.Red("✗ No attestations found with predicate type: %s\n"), opts.PredicateType)
		return err
	}
	attestations = filteredAttestations

	// print information about the policy that will be enforced against attestations
	logger.Println("\nThe following policy criteria will be enforced:")
	logger.Println(ec.BuildPolicyInformation())

	verified, errMsg, err := verifyAttestations(*artifact, attestations, sgVerifier, ec)
	if err != nil {
		logger.Println(logger.ColorScheme.Red(errMsg))
		return err
	}

	logger.Println(logger.ColorScheme.Green("✓ Verification succeeded!\n"))

	// If an exporter is provided with the --json flag, write the results to the terminal in JSON format
	if opts.exporter != nil {
		// print the results to the terminal as an array of JSON objects
		if err = opts.exporter.Write(logger.IO, verified); err != nil {
			logger.Println(logger.ColorScheme.Red("✗ Failed to write JSON output"))
			return err
		}
		return nil
	}

	logger.Printf("%s was attested by:\n", artifact.DigestWithAlg())

	// Otherwise print the results to the terminal in a table
	tableContent, err := buildTableVerifyContent(opts.Tenant, verified)
	if err != nil {
		logger.Println(logger.ColorScheme.Red("failed to parse results"))
		return err
	}

	headers := []string{"repo", "predicate_type", "workflow"}
	if err = logger.PrintTable(headers, tableContent); err != nil {
		logger.Println(logger.ColorScheme.Red("failed to print attestation details to table"))
		return err
	}

	// All attestations passed verification and policy evaluation
	return nil
}

func extractAttestationDetail(tenant, builderSignerURI string) (string, string, error) {
	// If given a build signer URI like
	// https://github.com/foo/bar/.github/workflows/release.yml@refs/heads/main
	// We want to extract:
	// * foo/bar
	// * .github/workflows/release.yml@refs/heads/main
	var orgAndRepoRegexp *regexp.Regexp
	var workflowRegexp *regexp.Regexp

	if tenant == "" {
		orgAndRepoRegexp = regexp.MustCompile(`https://github\.com/([^/]+/[^/]+)/`)
		workflowRegexp = regexp.MustCompile(`https://github\.com/[^/]+/[^/]+/(.+)`)
	} else {
		var tr = regexp.QuoteMeta(tenant)
		orgAndRepoRegexp = regexp.MustCompile(fmt.Sprintf(
			`https://%s\.ghe\.com/([^/]+/[^/]+)/`,
			tr))
		workflowRegexp = regexp.MustCompile(fmt.Sprintf(
			`https://%s\.ghe\.com/[^/]+/[^/]+/(.+)`,
			tr))
	}

	match := orgAndRepoRegexp.FindStringSubmatch(builderSignerURI)
	if len(match) < 2 {
		return "", "", fmt.Errorf("no match found for org and repo")
	}
	orgAndRepo := match[1]

	match = workflowRegexp.FindStringSubmatch(builderSignerURI)
	if len(match) < 2 {
		return "", "", fmt.Errorf("no match found for workflow")
	}
	workflow := match[1]

	return orgAndRepo, workflow, nil
}

func buildTableVerifyContent(tenant string, results []*verification.AttestationProcessingResult) ([][]string, error) {
	content := make([][]string, len(results))

	for i, res := range results {
		if res.VerificationResult == nil ||
			res.VerificationResult.Signature == nil ||
			res.VerificationResult.Signature.Certificate == nil {
			return nil, fmt.Errorf("bundle missing verification result fields")
		}
		builderSignerURI := res.VerificationResult.Signature.Certificate.Extensions.BuildSignerURI
		repoAndOrg, workflow, err := extractAttestationDetail(tenant, builderSignerURI)
		if err != nil {
			return nil, err
		}
		if res.VerificationResult.Statement == nil {
			return nil, fmt.Errorf("bundle missing attestation statement (bundle must originate from GitHub Artifact Attestations)")
		}
		predicateType := res.VerificationResult.Statement.PredicateType
		content[i] = []string{repoAndOrg, predicateType, workflow}
	}

	return content, nil
}

func newAPIClient(f *cmdutil.Factory, hostname string, logger *io.Handler) (api.Client, error) {
	hc, err := f.HttpClient()
	if err != nil {
		return nil, err
	}
	return api.NewLiveClient(hc, hostname, logger), nil
}

// configure tenancy if detected
func configureTenancy(apiClient api.Client, hostname string) (string, string, error) {
	td, err := apiClient.GetTrustDomain()
	if err != nil {
		return "", "", fmt.Errorf("error getting trust domain, make sure you are authenticated against the host: %w", err)
	}

	tenant, found := ghinstance.TenantName(hostname)
	if !found {
		return "", "", fmt.Errorf("invalid hostname provided: '%s'", hostname)
	}
	return td, tenant, nil
}
