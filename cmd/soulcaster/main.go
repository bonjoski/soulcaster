package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bonjoski/soulcaster/pkg/verifier"
	"github.com/bonjoski/soulcaster/pkg/version"
	"github.com/bonjoski/soulcaster/pkg/wrapper"
)

const (
	Banner = "Soulcaster %s — Runtime Hermetic Compiler Attestation\n"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "wrap":
		handleWrap(os.Args[2:])
	case "verify":
		handleVerify(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf(Banner, version.Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %q\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(Banner, version.Version)
	fmt.Println(`
Usage:
  soulcaster <command> [flags]

Commands:
  wrap     Wrap a compiler/build command, capture provenance, and emit in-toto SLSA attestation
  verify   Verify binary integrity and hermeticity against an in-toto attestation
  version  Display Soulcaster version

Run 'soulcaster <command> --help' for details on a specific command.`)
}

func handleWrap(args []string) {
	// Find '--' separator if present
	splitIdx := -1
	for i, arg := range args {
		if arg == "--" {
			splitIdx = i
			break
		}
	}

	var wrapFlags []string
	var buildCmd []string

	if splitIdx != -1 {
		wrapFlags = args[:splitIdx]
		buildCmd = args[splitIdx+1:]
	} else {
		// If no '--', check if there are flags followed by command
		// or standard flag parsing
		wrapFlags = args
	}

	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	outputBinary := fs.String("output-binary", "", "Explicit path to resulting binary")
	fs.StringVar(outputBinary, "o", "", "Alias for --output-binary")
	attestationPath := fs.String("attestation", "", "Output path for the attestation (default: <binary>.intoto.jsonl)")
	hermetic := fs.Bool("hermetic", true, "Enforce hermetic environment constraints (e.g. GOPROXY=off)")
	_ = fs.Bool("sign", false, "Cryptographically sign attestation (hardware/cosign)")

	if err := fs.Parse(wrapFlags); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing wrap flags: %v\n", err)
		os.Exit(1)
	}

	if splitIdx == -1 {
		buildCmd = fs.Args()
	}

	if len(buildCmd) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No build command specified.")
		fmt.Fprintln(os.Stderr, "Usage: soulcaster wrap [flags] -- <compiler-cmd> [args...]")
		os.Exit(1)
	}

	cfg := wrapper.Config{
		Command:         buildCmd,
		OutputBinary:    *outputBinary,
		AttestationPath: *attestationPath,
		Hermetic:        *hermetic,
		Version:         version.Version,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
	}

	res, err := wrapper.Wrap(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] Soulcaster Wrap Failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[SOULCASTER] Build wrapped successfully!\n")
	fmt.Printf("  Target Binary:    %s\n", res.OutputBinary)
	fmt.Printf("  Binary SHA-256:   %s\n", res.OutputDigest)
	fmt.Printf("  Source Files:     %d captured\n", res.SourceFilesCaptured)
	fmt.Printf("  Duration:         %s\n", res.ExecutionDuration)
	fmt.Printf("  Attestation File: %s\n", res.AttestationPath)
	fmt.Printf("  Hermetic Mode:    %t\n", *hermetic)
}

func handleVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	attestationPath := fs.String("attestation", "", "Path to in-toto SLSA attestation file")
	verifySources := fs.Bool("verify-sources", false, "Also verify local source file hashes match attestation")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing verify flags: %v\n", err)
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Target binary must be specified.")
		fmt.Fprintln(os.Stderr, "Usage: soulcaster verify --attestation <file.jsonl> <binary>")
		os.Exit(1)
	}

	binaryPath := remaining[0]
	attest := *attestationPath
	if attest == "" {
		attest = binaryPath + ".intoto.jsonl"
	}

	opts := verifier.Options{
		AttestationPath: attest,
		BinaryPath:      binaryPath,
		VerifySources:   *verifySources,
	}

	res, err := verifier.Verify(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[FAIL] %v\n", err)
		if res != nil && res.Message != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", res.Message)
		}
		os.Exit(1)
	}

	fmt.Printf("%s\n", res.Message)
	fmt.Printf("  Binary:           %s\n", res.BinaryPath)
	fmt.Printf("  Digest:           %s\n", res.ActualDigest)
	fmt.Printf("  Attestation:      %s\n", attest)
	fmt.Printf("  Source Files:     %d checked\n", res.SourceFilesVerified)
	fmt.Printf("  Hermetic Mode:    %t\n", res.HermeticMode)
}
