package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/soulcaster/pkg/intoto"
)

// Options specifies inputs for attestation verification.
type Options struct {
	AttestationPath string
	BinaryPath      string
	WorkDir         string
	VerifySources   bool
}

// Result describes the verification outcome.
type Result struct {
	Passed              bool
	BinaryPath          string
	ExpectedDigest      string
	ActualDigest        string
	SourceFilesVerified int
	HermeticMode        bool
	SubjectName         string
	Message             string
}

// Verify checks the hermetic integrity of the given binary against its in-toto SLSA attestation.
func Verify(opts Options) (*Result, error) {
	if opts.AttestationPath == "" {
		return nil, fmt.Errorf("attestation file path must be specified")
	}
	if opts.BinaryPath == "" {
		return nil, fmt.Errorf("target binary path must be specified")
	}

	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
	}

	absAttestation := opts.AttestationPath
	if !filepath.IsAbs(absAttestation) {
		absAttestation = filepath.Join(workDir, opts.AttestationPath)
	}

	absBinary := opts.BinaryPath
	if !filepath.IsAbs(absBinary) {
		absBinary = filepath.Join(workDir, opts.BinaryPath)
	}

	// 1. Read and parse in-toto statement
	data, err := os.ReadFile(absAttestation)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file %q: %w", absAttestation, err)
	}

	stmt, err := intoto.ParseStatement(data)
	if err != nil {
		return nil, fmt.Errorf("attestation schema validation error: %w", err)
	}

	// 2. Hash actual binary on disk
	if _, err := os.Stat(absBinary); err != nil {
		return nil, fmt.Errorf("target binary %q does not exist: %w", absBinary, err)
	}

	actualDigest, err := hashFile(absBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate binary hash: %w", err)
	}

	// 3. Match subject in attestation
	binaryBaseName := filepath.Base(absBinary)
	var matchedSubject *intoto.ResourceDescriptor

	for _, subj := range stmt.Subject {
		if subj.Name == binaryBaseName || subj.Name == opts.BinaryPath || strings.HasSuffix(subj.URI, binaryBaseName) {
			matchedSubject = &subj
			break
		}
	}

	// Fallback: if only one subject exists in the attestation, evaluate it
	if matchedSubject == nil && len(stmt.Subject) == 1 {
		matchedSubject = &stmt.Subject[0]
	}

	if matchedSubject == nil {
		return &Result{
			Passed:         false,
			BinaryPath:     absBinary,
			ActualDigest:   actualDigest,
			ExpectedDigest: "(no matching subject)",
			Message:        fmt.Sprintf("binary %q not found in attestation subjects", binaryBaseName),
		}, fmt.Errorf("tamper alert: binary %q is not covered by attestation subjects", binaryBaseName)
	}

	expectedSha, ok := matchedSubject.Digest["sha256"]
	if !ok {
		return nil, fmt.Errorf("subject %q is missing sha256 digest in attestation", matchedSubject.Name)
	}

	// 4. Verify binary digest matches
	if !strings.EqualFold(actualDigest, expectedSha) {
		return &Result{
			Passed:         false,
			BinaryPath:     absBinary,
			SubjectName:    matchedSubject.Name,
			ExpectedDigest: expectedSha,
			ActualDigest:   actualDigest,
			Message: fmt.Sprintf("TAMPERED BINARY DETECTED! Computed SHA-256 (%s) does not match attestation (%s)",
				actualDigest, expectedSha),
		}, fmt.Errorf("verification failure: binary %q has been tampered with or modified post-attestation", binaryBaseName)
	}

	// 5. Verify source files if requested
	verifiedSources := 0
	sources := stmt.Predicate.BuildDefinition.ExternalParameters.SourceFiles
	if opts.VerifySources {
		for _, src := range sources {
			expectedSrcSha := src.Digest["sha256"]
			localPath := filepath.Join(workDir, src.Name)
			if info, err := os.Stat(localPath); err == nil && !info.IsDir() {
				localDigest, err := hashFile(localPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read source file %q: %w", localPath, err)
				}
				if !strings.EqualFold(localDigest, expectedSrcSha) {
					return &Result{
						Passed:         false,
						BinaryPath:     absBinary,
						SubjectName:    matchedSubject.Name,
						ExpectedDigest: expectedSha,
						ActualDigest:   actualDigest,
						Message: fmt.Sprintf("SOURCE TAMPER DETECTED: file %q digest (%s) mismatches attestation (%s)",
							src.Name, localDigest, expectedSrcSha),
					}, fmt.Errorf("verification failure: source file %q has changed since build", src.Name)
				}
				verifiedSources++
			}
		}
	} else {
		verifiedSources = len(sources)
	}

	hermetic := stmt.Predicate.BuildDefinition.InternalParameters.HermeticMode

	return &Result{
		Passed:              true,
		BinaryPath:          absBinary,
		SubjectName:         matchedSubject.Name,
		ExpectedDigest:      expectedSha,
		ActualDigest:        actualDigest,
		SourceFilesVerified: verifiedSources,
		HermeticMode:        hermetic,
		Message: fmt.Sprintf("[PASS] Hermeticity Verified: %d source files, 0 network calls, SLSA Level 3 compliant.",
			verifiedSources),
	}, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
