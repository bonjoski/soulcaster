package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/bonjoski/soulcaster/pkg/receipt"
	"github.com/bonjoski/soulcaster/pkg/ux"
	"github.com/bonjoski/soulcaster/pkg/version"
)

func runReceipt(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receipt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	artifactPath := fs.String("artifact", "", "Path to the built artifact to attest")
	outPath := fs.String("out", "", "Output path for in-toto v1.0 / SLSA v1.0 JSONL receipt")
	fs.StringVar(outPath, "o", "", "Alias for --out")
	asJSON := fs.Bool("json", false, "Emit in-toto / SLSA v1.0 receipt JSON (or FixForwardError JSON) directly to stdout/stderr")
	showWhy := fs.Bool("why", false, "Show progressive-disclosure explanation of local SLSA v1.0 receipts")
	showHelp := fs.Bool("help", false, "Show usage for soulcaster receipt")
	fs.BoolVar(showHelp, "h", false, "Alias for --help")

	if err := fs.Parse(args); err != nil {
		ffe := &ux.FixForwardError{
			Tool:           "soulcaster",
			Code:           "SOULCASTER_RECEIPT_INVALID_FLAGS",
			Summary:        fmt.Sprintf("Invalid receipt flag: %v", err),
			RemediationCmd: "soulcaster receipt --artifact dist/app --out receipts/provenance.intoto.jsonl",
			WhyOneLiner:    "Supported flags: --artifact <path>, --out <path>, --json, --why.",
			DeepWhy:        "Run `soulcaster receipt --help` or `soulcaster explain receipt --why` to inspect local provenance receipt options.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, *asJSON, *showWhy)
		return 1
	}

	if *showHelp {
		_, _ = fmt.Fprintln(stdout, `Usage: soulcaster receipt --artifact <path> [--out <path>] [--json] [--why]

Generates a portable, 100% local in-toto v1.0 / SLSA v1.0 provenance receipt JSONL
using os.OpenRoot / O_NOFOLLOW symlink defense and zero cloud calls.

Flags:
  --artifact <path>   Path to the built artifact (also accepted as positional arg)
  --out, -o <path>    Destination path for provenance JSONL (default: <artifact>.intoto.jsonl when not --json)
  --json              Emit machine-readable JSONL receipt to stdout (or FixForwardError JSON on stderr)
  --why               Show progressive disclosure of the local SLSA v1.0 receipt contract`)
		return 0
	}

	target := strings.TrimSpace(*artifactPath)
	if target == "" && fs.NArg() > 0 {
		target = strings.TrimSpace(fs.Arg(0))
	}

	if target == "" {
		ffe := &ux.FixForwardError{
			Tool:           "soulcaster",
			Code:           "SOULCASTER_RECEIPT_MISSING_ARTIFACT",
			Summary:        "Specify an artifact path to generate a local SLSA v1.0 provenance receipt",
			RemediationCmd: "soulcaster receipt --artifact dist/app --out receipts/provenance.intoto.jsonl",
			WhyOneLiner:    "Soulcaster computes the artifact's SHA-256 digest and binds it to local git/builder metadata.",
			DeepWhy:        "Local provenance receipts follow the open-standard in-toto v1.0 Statement and SLSA v1.0 Provenance schema with zero SaaS dependencies, enabling offline and GitHub Actions verification.",
			References:     []string{"https://slsa.dev/spec/v1.0/provenance"},
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, *asJSON, *showWhy)
		return 1
	}

	dest := strings.TrimSpace(*outPath)
	if dest == "" && !*asJSON {
		dest = target + ".intoto.jsonl"
	}

	res, err := receipt.Generate(receipt.Options{
		ArtifactPath: target,
		OutputPath:   dest,
		Version:      version.Version,
	})
	if err != nil {
		code := "SOULCASTER_RECEIPT_ARTIFACT_ERROR"
		summary := fmt.Sprintf("Could not generate receipt: %v", err)
		why := "Soulcaster verifies regular files fail-closed before issuing provenance digests."
		deep := "Ensure the artifact exists as a regular file inside your workspace. Symlinks, directories, and FIFOs are rejected fail-closed via os.OpenRoot + O_NOFOLLOW to prevent host file substitution."
		if errors.Is(err, receipt.ErrSymlinkArtifact) {
			code = "SOULCASTER_RECEIPT_SYMLINK_REJECTED"
			summary = "Refused symbolic link path while generating local provenance receipt"
			why = "Symlink targets are blocked via os.OpenRoot + O_NOFOLLOW to prevent host-file substitution attacks."
		}
		ffe := &ux.FixForwardError{
			Tool:           "soulcaster",
			Code:           code,
			Summary:        summary,
			RemediationCmd: "soulcaster explain receipt --why",
			WhyOneLiner:    why,
			DeepWhy:        deep,
			References:     []string{"CWE-59", "CWE-367", "https://slsa.dev/spec/v1.0/provenance"},
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, *asJSON, *showWhy)
		return 1
	}

	if *asJSON {
		_, _ = stdout.Write(res.JSONL)
		return 0
	}

	shortSHA := res.SHA256
	if len(shortSHA) > 16 {
		shortSHA = shortSHA[:16]
	}
	cleanName := ux.SanitizeTerminalText(res.Statement.Subject[0].Name)
	cleanOut := ux.SanitizeTerminalText(res.OutputPath)

	_, _ = fmt.Fprintf(stdout, "✓ soulcaster: emitted SLSA v1.0 receipt for %s (sha256:%s…)\n", cleanName, shortSHA)
	_, _ = fmt.Fprintf(stdout, "  File: %s\n", cleanOut)
	if *showWhy {
		_, _ = fmt.Fprintf(stdout, "  Why:  Portable local in-toto v1.0 / SLSA v1.0 proof verifiable offline or in GitHub Actions with zero cloud control plane.\n")
		_, _ = fmt.Fprintf(stdout, "\n  Deep Dive (--why):\n")
		_, _ = fmt.Fprintf(stdout, "  Subject SHA-256: %s (%d bytes)\n", res.SHA256, res.ArtifactSize)
		if res.Git.Commit != "" {
			_, _ = fmt.Fprintf(stdout, "  Local Git State: commit=%s branch=%s dirty=%t\n", res.Git.Commit, ux.SanitizeTerminalText(res.Git.Branch), res.Git.Dirty)
		}
		_, _ = fmt.Fprintf(stdout, "  Symlink Defense: opened strictly via os.OpenRoot + O_NOFOLLOW (zero cloud calls).\n")
		_, _ = fmt.Fprintf(stdout, "  Ref:  https://slsa.dev/spec/v1.0/provenance\n")
	} else {
		_, _ = fmt.Fprintf(stdout, "  Why:  Portable local in-toto v1.0 proof verifiable in CI with zero cloud control plane (re-run with --why for details).\n")
	}

	return 0
}
