package verifier

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/bonjoski/soulcaster/pkg/wrapper"
)

const maxAttestationBytes = 32 << 20 // 32 MiB max attestation file size

// Options specifies inputs for attestation verification.
type Options struct {
	AttestationPath  string
	BinaryPath       string
	WorkDir          string
	VerifySources    bool
	PublicKey        string
	TrustedKeys      []ed25519.PublicKey
	AllowUnsignedDev bool
}

// Result describes the verification outcome.
type Result struct {
	Passed              bool
	Signed              bool
	VerifiedKeyID       string
	BinaryPath          string
	ExpectedDigest      string
	ActualDigest        string
	SourceFilesVerified int
	HermeticMode        bool
	SubjectName         string
	Message             string
}

// Verify checks the cryptographic DSSE signature and hermetic integrity of the given binary
// against its in-toto SLSA attestation.
func Verify(opts Options) (*Result, error) {
	if opts.AttestationPath == "" {
		return nil, errors.New("attestation file path must be specified")
	}
	if opts.BinaryPath == "" {
		return nil, errors.New("target binary path must be specified")
	}

	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
	}
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve working directory: %w", err)
	}

	absAttestation := opts.AttestationPath
	if !filepath.IsAbs(absAttestation) {
		absAttestation = filepath.Join(absWorkDir, opts.AttestationPath)
	}

	absBinary := opts.BinaryPath
	if !filepath.IsAbs(absBinary) {
		absBinary = filepath.Join(absWorkDir, opts.BinaryPath)
	}

	// 1. Resolve trusted Ed25519 public keys.
	trustedKeys, err := collectTrustedKeys(opts)
	if err != nil {
		return nil, err
	}
	if !opts.AllowUnsignedDev && len(trustedKeys) == 0 {
		return nil, errors.New("signature verification required: provide --public-key or SOULCASTER_PUBLIC_KEY (or --allow-unsigned-dev for local development)")
	}

	// 2. Read bounded attestation payload and verify DSSE signature (unless explicit dev mode).
	data, err := readBoundedFile(absAttestation, maxAttestationBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file %q: %w", absAttestation, err)
	}

	var stmt *intoto.Statement
	var signed bool
	var verifiedKeyID string
	if !opts.AllowUnsignedDev || len(trustedKeys) > 0 {
		stmt, verifiedKeyID, err = intoto.VerifyDSSE(data, trustedKeys...)
		if err != nil {
			return &Result{
				Passed:     false,
				Signed:     false,
				BinaryPath: absBinary,
				Message:    fmt.Sprintf("ATTESTATION SIGNATURE VERIFICATION FAILED: %v", err),
			}, fmt.Errorf("attestation signature verification failed: %w", err)
		}
		signed = true
	} else {
		stmt, err = intoto.ParseStatement(data)
		if err != nil {
			return nil, fmt.Errorf("attestation schema validation error: %w", err)
		}
	}

	// 3. Hash actual binary on disk.
	if _, err := os.Stat(absBinary); err != nil {
		return nil, fmt.Errorf("target binary %q does not exist: %w", absBinary, err)
	}

	actualDigest, err := hashFile(absBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate binary hash: %w", err)
	}

	// 4. Match subject in attestation.
	binaryBaseName := filepath.Base(absBinary)
	var matchedSubject *intoto.ResourceDescriptor
	for i := range stmt.Subject {
		subj := &stmt.Subject[i]
		if subj.Name == binaryBaseName || subj.Name == opts.BinaryPath || strings.HasSuffix(subj.URI, binaryBaseName) {
			matchedSubject = subj
			break
		}
	}
	if matchedSubject == nil && len(stmt.Subject) == 1 {
		matchedSubject = &stmt.Subject[0]
	}
	if matchedSubject == nil {
		return &Result{
			Passed:         false,
			Signed:         signed,
			VerifiedKeyID:  verifiedKeyID,
			BinaryPath:     absBinary,
			ActualDigest:   actualDigest,
			ExpectedDigest: "(no matching subject)",
			Message:        fmt.Sprintf("binary %q not found in attestation subjects", binaryBaseName),
		}, fmt.Errorf("tamper alert: binary %q is not covered by attestation subjects", binaryBaseName)
	}

	expectedSha, ok := matchedSubject.Digest["sha256"]
	if !ok || expectedSha == "" {
		return nil, fmt.Errorf("subject %q is missing sha256 digest in attestation", matchedSubject.Name)
	}

	// 5. Verify binary digest matches.
	if !strings.EqualFold(actualDigest, expectedSha) {
		return &Result{
			Passed:         false,
			Signed:         signed,
			VerifiedKeyID:  verifiedKeyID,
			BinaryPath:     absBinary,
			SubjectName:    matchedSubject.Name,
			ExpectedDigest: expectedSha,
			ActualDigest:   actualDigest,
			Message: fmt.Sprintf("TAMPERED BINARY DETECTED! Computed SHA-256 (%s) does not match attestation (%s)",
				actualDigest, expectedSha),
		}, fmt.Errorf("verification failure: binary %q has been tampered with or modified post-attestation", binaryBaseName)
	}

	// 6. Verify source files fail-closed if requested.
	verifiedSources := 0
	sources := stmt.Predicate.BuildDefinition.ExternalParameters.SourceFiles
	if opts.VerifySources {
		if err := verifyWorkspaceSources(absWorkDir, absBinary, absAttestation, sources); err != nil {
			return &Result{
				Passed:         false,
				Signed:         signed,
				VerifiedKeyID:  verifiedKeyID,
				BinaryPath:     absBinary,
				SubjectName:    matchedSubject.Name,
				ExpectedDigest: expectedSha,
				ActualDigest:   actualDigest,
				Message:        fmt.Sprintf("SOURCE TAMPER DETECTED: %v", err),
			}, fmt.Errorf("verification failure: %w", err)
		}
		verifiedSources = len(sources)
	} else {
		verifiedSources = len(sources)
	}

	hermetic := stmt.Predicate.BuildDefinition.InternalParameters.HermeticMode
	msg := fmt.Sprintf("[PASS]Unsigned-Dev Integrity Checked: %d source files (NOT SLSA Level 3 signed).", verifiedSources)
	if signed {
		msg = fmt.Sprintf("[PASS] Signed Attestation & Integrity Verified (key=%s): %d source files, hermetic=%t.",
			verifiedKeyID, verifiedSources, hermetic)
	}

	return &Result{
		Passed:              true,
		Signed:              signed,
		VerifiedKeyID:       verifiedKeyID,
		BinaryPath:          absBinary,
		SubjectName:         matchedSubject.Name,
		ExpectedDigest:      expectedSha,
		ActualDigest:        actualDigest,
		SourceFilesVerified: verifiedSources,
		HermeticMode:        hermetic,
		Message:             msg,
	}, nil
}

func collectTrustedKeys(opts Options) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(opts.TrustedKeys)+2)
	for _, k := range opts.TrustedKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trusted Ed25519 public key length %d", len(k))
		}
		keys = append(keys, k)
	}

	for _, spec := range []string{opts.PublicKey, os.Getenv("SOULCASTER_PUBLIC_KEY")} {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		pub, err := intoto.ParseEd25519PublicKey(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted Ed25519 public key: %w", err)
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

func verifyWorkspaceSources(absWorkDir, absBinary, absAttestation string, sources []intoto.ResourceDescriptor) error {
	realWorkDir, err := filepath.EvalSymlinks(absWorkDir)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace root %q: %w", absWorkDir, err)
	}

	attestedSet := make(map[string]bool, len(sources))
	for _, src := range sources {
		if src.Name == "" || strings.ContainsRune(src.Name, 0) {
			return errors.New("attestation contains empty or NUL source file path")
		}
		fromSlash := filepath.FromSlash(src.Name)
		if filepath.IsAbs(fromSlash) {
			return fmt.Errorf("source path %q must be relative to workspace", src.Name)
		}
		cleanRel := filepath.Clean(fromSlash)
		if cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("source path traversal rejected: %q escapes workspace", src.Name)
		}

		expectedSrcSha := src.Digest["sha256"]
		if expectedSrcSha == "" {
			return fmt.Errorf("source file %q is missing sha256 digest in attestation", src.Name)
		}

		localPath := filepath.Join(absWorkDir, cleanRel)
		linfo, err := os.Lstat(localPath)
		if err != nil {
			return fmt.Errorf("attested source file %q is missing on disk: %w", src.Name, err)
		}
		if linfo.IsDir() {
			return fmt.Errorf("attested source file %q is a directory on disk", src.Name)
		}

		realLocal, err := filepath.EvalSymlinks(localPath)
		if err != nil {
			return fmt.Errorf("failed to resolve source path %q: %w", src.Name, err)
		}
		if !wrapper.IsWithinDir(realWorkDir, realLocal) {
			return fmt.Errorf("symlink escape detected: source file %q resolves outside workspace", src.Name)
		}

		localDigest, err := hashFile(realLocal)
		if err != nil {
			return fmt.Errorf("failed to read source file %q: %w", localPath, err)
		}
		if !strings.EqualFold(localDigest, expectedSrcSha) {
			return fmt.Errorf("source file %q has changed since build (got %s, want %s)", src.Name, localDigest, expectedSrcSha)
		}
		attestedSet[filepath.ToSlash(cleanRel)] = true
	}

	// Ensure no unattested source/manifest/vendor files were added to workDir.
	diskFiles, err := wrapper.ScanSourceFiles(absWorkDir)
	if err != nil {
		return fmt.Errorf("workspace source scan failed: %w", err)
	}
	cleanBin := filepath.Clean(absBinary)
	cleanAttest := filepath.Clean(absAttestation)
	for _, f := range diskFiles {
		cleanDisk := filepath.Clean(f.Path)
		if cleanDisk == cleanBin || cleanDisk == cleanAttest {
			continue
		}
		if !attestedSet[f.RelPath] {
			return fmt.Errorf("unattested source file %q found in workspace", f.RelPath)
		}
	}
	return nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum allowed size (%d bytes)", path, maxBytes)
	}
	return data, nil
}

func hashFile(path string) (string, error) {
	return wrapper.HashFile(path)
}
