package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/bonjoski/soulcaster/pkg/verifier"
)

func handleVerifyVariant(args []string) {
	fs := flag.NewFlagSet("verify-variant", flag.ExitOnError)
	diffPath := fs.String("diff", "", "Path to patch diff file to inspect")
	targetBinary := fs.String("target-binary", "", "Optional compiled binary to check for hardening flags")
	testCmd := fs.String("test-cmd", "", "Command to execute test/variant suite")
	attestationPath := fs.String("output-attestation", "", "Output path for the in-toto gate attestation")
	fs.StringVar(attestationPath, "o", "", "Alias for --output-attestation")
	jsonOutput := fs.Bool("json", false, "Output machine-readable JSON diagnostic proof")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing verify-variant flags: %v\n", err)
		os.Exit(1)
	}

	if *diffPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --diff flag is required.")
		fmt.Fprintln(os.Stderr, "Usage: soulcaster verify-variant --diff <patch.diff> [--target-binary <binary>] [--test-cmd <cmd>] [--json]")
		os.Exit(1)
	}

	opts := verifier.VariantVerificationOptions{
		DiffPath:        *diffPath,
		TargetBinary:    *targetBinary,
		TestCmd:         *testCmd,
		AttestationPath: *attestationPath,
	}

	res, err := verifier.VerifyVariant(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Soulcaster verify-variant failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		fmt.Println(res.DiagnosticJSON)
	} else {
		fmt.Print(res.Summary)
		if res.Passed && res.AttestationPath != "" {
			fmt.Printf("  Attestation Emitted: %s\n", res.AttestationPath)
			fmt.Printf("  Predicate Type:      %s\n", intoto.VariantGatePredicateTypeV1)
		}
	}

	if !res.Passed {
		os.Exit(1)
	}
}
