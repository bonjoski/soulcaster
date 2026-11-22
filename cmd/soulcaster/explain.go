package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/bonjoski/soulcaster/pkg/ux"
)

func runExplain(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	showWhy := false
	topic := "receipt"

	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--why":
			showWhy = true
		case "-h", "--help", "help":
			_, _ = fmt.Fprintln(stdout, "Usage: soulcaster explain [receipt|slsa|toctou|verify-patch] [--why] [--json]")
			return 0
		default:
			if !strings.HasPrefix(a, "-") {
				topic = strings.ToLower(strings.TrimSpace(a))
			}
		}
	}

	switch topic {
	case "", "soulcaster_receipt_missing_artifact", "soulcaster_receipt_symlink_rejected", "soulcaster_receipt_artifact_error":
		topic = "receipt"
	case "in-toto", "provenance":
		topic = "slsa"
	case "patch", "ast":
		topic = "verify-patch"
	}

	explanations := map[string]*ux.FixForwardError{
		"receipt": {
			Tool:           "soulcaster",
			Code:           "SOULCASTER_EXPLAIN_RECEIPT",
			Summary:        "Portable 100% local in-toto v1.0 / SLSA v1.0 provenance receipts with zero cloud control plane",
			RemediationCmd: "soulcaster receipt --artifact dist/app --out receipts/provenance.intoto.jsonl",
			WhyOneLiner:    "Binds your built binary's SHA-256 digest to local git metadata in standard JSONL verifiable in GitHub Actions.",
			DeepWhy:        "Running `soulcaster receipt --artifact <path>` opens the target strictly via os.OpenRoot + O_NOFOLLOW (rejecting symlink swaps), computes its SHA-256 digest, captures local builder/timestamp/git metadata with zero network calls, and emits single-line in-toto v1.0 / SLSA v1.0 JSONL compatible with verify-local-receipts.yml and paved-road-release.yml.",
			References:     []string{"https://slsa.dev/spec/v1.0/provenance", "https://github.com/in-toto/attestation"},
			ExitCode:       0,
		},
		"slsa": {
			Tool:           "soulcaster",
			Code:           "SOULCASTER_EXPLAIN_SLSA",
			Summary:        "SLSA v1.0 / in-toto v1.0 build provenance attestations for reproducible software supply chains",
			RemediationCmd: "soulcaster wrap -o bin/app -- go build -o bin/app .",
			WhyOneLiner:    "Proves exactly which compiler, source files, and hermetic flags produced a binary artifact.",
			DeepWhy:        "SLSA (Supply-chain Levels for Software Artifacts) v1.0 separates the envelope (in-toto Statement v1, optionally wrapped in DSSE Ed25519) from the provenance predicate (buildDefinition + runDetails). Soulcaster records input source hashes, compiler digests, and clean-room flags (GOPROXY=off, GOSUMDB=off) locally so downstream verifiers can detect tampering offline.",
			References:     []string{"https://slsa.dev/spec/v1.0/levels", "CWE-494"},
			ExitCode:       0,
		},
		"toctou": {
			Tool:           "soulcaster",
			Code:           "SOULCASTER_EXPLAIN_TOCTOU",
			Summary:        "Time-of-Check to Time-of-Use (TOCTOU) defense against mid-build source and symlink tampering",
			RemediationCmd: "soulcaster verify --verify-sources --attestation bin/app.intoto.jsonl bin/app",
			WhyOneLiner:    "Defeats in-flight source swaps and symlink escapes between pre-build hashing and artifact output.",
			DeepWhy:        "Build-time attackers can swap source files mid-compilation (AB-BA races) or plant symlinks pointing to host files. Soulcaster stages workspaces into read-only snapshots during `wrap`, re-verifies source digests post-build, and opens receipt targets with os.OpenRoot + O_NOFOLLOW + inode verification so any symlink or mid-flight swap fails closed.",
			References:     []string{"CWE-367", "CWE-59"},
			ExitCode:       0,
		},
		"verify-patch": {
			Tool:           "soulcaster",
			Code:           "SOULCASTER_EXPLAIN_VERIFY_PATCH",
			Summary:        "Differential AST security gate detecting secondary vulnerabilities introduced by patches",
			RemediationCmd: "soulcaster verify-patch --base main --head HEAD --json",
			WhyOneLiner:    "Catches AI-generated or rushed patches that fix one bug while introducing a new security flaw.",
			DeepWhy:        "`soulcaster verify-patch` parses base and head ASTs (Go, Python, Rust) across a unified diff or git range to flag dangerous regressions (command injection, disabled TLS checks, unsafe deserialization, auth bypasses) and emits an in-toto Secondary Vulnerability Gate attestation.",
			References:     []string{"OWASP-LLM02", "CWE-78"},
			ExitCode:       0,
		},
	}

	entry, ok := explanations[topic]
	if !ok {
		ffe := &ux.FixForwardError{
			Tool:           "soulcaster",
			Code:           "SOULCASTER_EXPLAIN_UNKNOWN_TOPIC",
			Summary:        fmt.Sprintf("Unknown explain topic %q", topic),
			RemediationCmd: "soulcaster explain receipt --why",
			WhyOneLiner:    "Available topics: receipt, slsa, toctou, verify-patch.",
			DeepWhy:        "Run `soulcaster explain <topic> --why` with one of: receipt, slsa, toctou, verify-patch.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, asJSON, showWhy)
		return 1
	}

	if err := entry.Render(stdout, asJSON, showWhy); err != nil {
		return 1
	}
	return 0
}
