package receipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/bonjoski/soulcaster/pkg/ux"
	"github.com/google/uuid"
)

const (
	// ReceiptBuildTypeV1 identifies portable local workstation provenance receipts.
	ReceiptBuildTypeV1 = "https://bonjoski.github.io/soulcaster/local-receipt/v1"

	maxReceiptBytes  = 32 << 20 // 32 MiB max receipt file size
	maxArtifactBytes = 2 << 30  // 2 GiB safety cap for local artifact hashing
)

var (
	// ErrSymlinkArtifact is returned when an artifact or output path is a symlink.
	ErrSymlinkArtifact = errors.New("symlink artifact rejected")
	// ErrNonRegularArtifact is returned when an artifact is a directory, FIFO, or device.
	ErrNonRegularArtifact = errors.New("non-regular artifact rejected")
	// ErrDigestMismatch is returned when an artifact digest does not match its receipt.
	ErrDigestMismatch = errors.New("artifact digest mismatch")
)

// Options configures local SLSA v1.0 / in-toto v1.0 provenance receipt generation.
type Options struct {
	ArtifactPath string
	OutputPath   string // Optional; if empty, Generate does not write to disk unless caller writes JSONL.
	WorkDir      string // Optional; defaults to current working directory.
	Version      string // Soulcaster version string.
}

// GitMetadata captures local-only repository state (zero network calls).
type GitMetadata struct {
	Commit string
	Branch string
	Dirty  bool
}

// Result holds the generated in-toto / SLSA v1.0 receipt and metadata.
type Result struct {
	Statement    *intoto.Statement
	JSONL        []byte
	ArtifactPath string
	OutputPath   string
	SHA256       string
	ArtifactSize int64
	GeneratedAt  time.Time
	Git          GitMetadata
}

// Generate creates a portable, 100% local in-toto v1.0 / SLSA v1.0 provenance receipt
// for the target artifact using os.OpenRoot + O_NOFOLLOW symlink defense and zero cloud calls.
func Generate(opts Options) (*Result, error) {
	if strings.TrimSpace(opts.ArtifactPath) == "" {
		return nil, errors.New("artifact path is required")
	}
	if strings.ContainsRune(opts.ArtifactPath, 0) {
		return nil, errors.New("artifact path contains NUL byte")
	}

	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve working directory: %w", err)
		}
	}
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve working directory: %w", err)
	}

	absArtifact := opts.ArtifactPath
	if !filepath.IsAbs(absArtifact) {
		absArtifact = filepath.Join(absWorkDir, opts.ArtifactPath)
	}
	absArtifact = filepath.Clean(absArtifact)

	digestHex, sizeBytes, err := hashArtifactNoFollow(absArtifact)
	if err != nil {
		return nil, err
	}

	ver := strings.TrimSpace(opts.Version)
	if ver == "" {
		ver = "0.1.0"
	}

	now := time.Now().UTC()
	gitMeta := collectLocalGitMetadata(absWorkDir)

	baseName := ux.SanitizeTerminalText(filepath.Base(absArtifact))
	relURI := filepath.ToSlash(absArtifact)
	if rel, rErr := filepath.Rel(absWorkDir, absArtifact); rErr == nil && !strings.HasPrefix(rel, "..") {
		relURI = filepath.ToSlash(rel)
	}

	annotations := map[string]string{
		"generatedAt": now.Format(time.RFC3339),
		"sizeBytes":   fmt.Sprintf("%d", sizeBytes),
		"builderOS":   runtime.GOOS,
		"builderArch": runtime.GOARCH,
		"localOnly":   "true",
	}
	if gitMeta.Commit != "" {
		annotations["gitCommit"] = gitMeta.Commit
	}
	if gitMeta.Branch != "" {
		annotations["gitBranch"] = gitMeta.Branch
	}
	if gitMeta.Commit != "" {
		annotations["gitDirty"] = fmt.Sprintf("%t", gitMeta.Dirty)
	}

	subject := []intoto.ResourceDescriptor{
		{
			Name:        baseName,
			URI:         "file://" + ux.SanitizeTerminalText(relURI),
			Digest:      intoto.DigestSet{"sha256": digestHex},
			Annotations: annotations,
		},
	}

	env := map[string]string{
		"LOCAL_RECEIPT": "true",
		"GOOS":          runtime.GOOS,
		"GOARCH":        runtime.GOARCH,
	}
	if gitMeta.Branch != "" {
		env["GIT_BRANCH"] = gitMeta.Branch
	}
	if gitMeta.Commit != "" {
		env["GIT_COMMIT"] = gitMeta.Commit
		env["GIT_DIRTY"] = fmt.Sprintf("%t", gitMeta.Dirty)
	}

	internal := intoto.InternalParameters{
		SoulcasterVersion: ver,
		WorkingDir:        ux.SanitizeTerminalText(absWorkDir),
		HermeticMode:      true,
	}

	stmt := intoto.NewStatement(
		subject,
		[]string{"soulcaster", "receipt", "--artifact", baseName},
		[]intoto.ResourceDescriptor{},
		env,
		internal,
		&now,
		&now,
		uuid.New().String(),
		[]intoto.ResourceDescriptor{
			{
				Name: "localReceiptMetadata",
				Annotations: map[string]string{
					"localOnly":      "true",
					"cloudCalls":     "0",
					"symlinkDefense": "os.OpenRoot+O_NOFOLLOW",
				},
			},
		},
	)
	stmt.Predicate.BuildDefinition.BuildType = ReceiptBuildTypeV1
	stmt.Predicate.RunDetails.Builder.Version = map[string]string{
		"soulcaster": ver,
		"go":         runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
	if gitMeta.Commit != "" {
		stmt.Predicate.BuildDefinition.ResolvedDependencies = []intoto.ResourceDescriptor{
			{
				Name: "git-head",
				URI:  "git+local://.",
				Digest: intoto.DigestSet{
					"gitCommit": gitMeta.Commit,
				},
				Annotations: map[string]string{
					"branch": gitMeta.Branch,
					"dirty":  fmt.Sprintf("%t", gitMeta.Dirty),
				},
			},
		}
	}

	if err := stmt.Validate(); err != nil {
		return nil, fmt.Errorf("generated receipt failed in-toto validation: %w", err)
	}

	jsonl, err := stmt.ToJSONL()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize receipt JSONL: %w", err)
	}

	outPath := opts.OutputPath
	if outPath != "" {
		if !filepath.IsAbs(outPath) {
			outPath = filepath.Join(absWorkDir, outPath)
		}
		outPath = filepath.Clean(outPath)
		if err := writeReceiptSafely(outPath, jsonl); err != nil {
			return nil, err
		}
	}

	return &Result{
		Statement:    stmt,
		JSONL:        jsonl,
		ArtifactPath: absArtifact,
		OutputPath:   outPath,
		SHA256:       digestHex,
		ArtifactSize: sizeBytes,
		GeneratedAt:  now,
		Git:          gitMeta,
	}, nil
}

// VerifyReceipt validates a local in-toto v1.0 / SLSA v1.0 receipt against an artifact on disk,
// rejecting symlinks and failing closed on any SHA-256 digest mismatch.
func VerifyReceipt(receiptPath, artifactPath string) (*intoto.Statement, error) {
	if strings.TrimSpace(receiptPath) == "" || strings.TrimSpace(artifactPath) == "" {
		return nil, errors.New("receipt path and artifact path are required")
	}

	raw, err := readRegularNoFollow(receiptPath, maxReceiptBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read receipt %q: %w", receiptPath, err)
	}

	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) == 0 || len(bytes.TrimSpace(lines[0])) == 0 {
		return nil, errors.New("empty provenance receipt")
	}

	var stmt *intoto.Statement
	for _, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		// Support either DSSE envelope or raw in-toto statement (matching verify-local-receipts.yml)
		var env struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		}
		if json.Unmarshal(ln, &env) == nil && env.Payload != "" && env.PayloadType != "" {
			decoded, dErr := base64.StdEncoding.DecodeString(env.Payload)
			if dErr != nil {
				return nil, fmt.Errorf("failed to decode DSSE payload: %w", dErr)
			}
			stmt, err = intoto.ParseStatement(decoded)
		} else {
			stmt, err = intoto.ParseStatement(ln)
		}
		if err != nil {
			return nil, err
		}
		break
	}
	if stmt == nil {
		return nil, errors.New("no valid in-toto statement found in receipt")
	}

	actualDigest, _, err := hashArtifactNoFollow(artifactPath)
	if err != nil {
		return nil, err
	}

	matched := false
	var expectedDigest string
	for _, subj := range stmt.Subject {
		exp := strings.ToLower(strings.TrimSpace(subj.Digest["sha256"]))
		if exp == "" {
			continue
		}
		if expectedDigest == "" {
			expectedDigest = exp
		}
		if len(exp) == len(actualDigest) && subtle.ConstantTimeCompare([]byte(exp), []byte(actualDigest)) == 1 {
			matched = true
			break
		}
	}

	if !matched {
		return nil, fmt.Errorf("%w: artifact sha256 %s does not match receipt sha256 %s",
			ErrDigestMismatch, actualDigest, expectedDigest)
	}

	return stmt, nil
}

// hashArtifactNoFollow computes the SHA-256 digest of a regular file using os.OpenRoot + O_NOFOLLOW
// and Lstat/Fstat inode verification so symlink swaps fail closed.
func hashArtifactNoFollow(path string) (string, int64, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to resolve artifact path: %w", err)
	}
	absPath = filepath.Clean(absPath)

	// Pre-check Lstat on target path to give an explicit symlink error even before opening root.
	linfo, err := os.Lstat(absPath)
	if err != nil {
		return "", 0, fmt.Errorf("artifact not accessible: %w", err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("%w: %q is a symbolic link", ErrSymlinkArtifact, filepath.Base(absPath))
	}
	if !linfo.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %q is not a regular file", ErrNonRegularArtifact, filepath.Base(absPath))
	}

	parentDir := filepath.Dir(absPath)
	baseName := filepath.Base(absPath)

	root, err := os.OpenRoot(parentDir)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open artifact root directory: %w", err)
	}
	defer root.Close()

	rootLinfo, err := root.Lstat(baseName)
	if err != nil {
		return "", 0, fmt.Errorf("artifact stat failed inside root: %w", err)
	}
	if rootLinfo.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("%w: %q is a symbolic link", ErrSymlinkArtifact, baseName)
	}
	if !rootLinfo.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %q is not a regular file", ErrNonRegularArtifact, baseName)
	}

	f, err := openRegularNoFollow(root, baseName)
	if err != nil {
		if isSymlinkOpenErr(err) {
			return "", 0, fmt.Errorf("%w: %q refused by O_NOFOLLOW", ErrSymlinkArtifact, baseName)
		}
		return "", 0, fmt.Errorf("failed to open artifact: %w", err)
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("failed to fstat opened artifact: %w", err)
	}
	if !finfo.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %q is not a regular file", ErrNonRegularArtifact, baseName)
	}
	if !os.SameFile(rootLinfo, finfo) {
		return "", 0, fmt.Errorf("%w: file identity changed between lstat and open (TOCTOU)", ErrSymlinkArtifact)
	}

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArtifactBytes+1))
	if err != nil {
		return "", 0, fmt.Errorf("failed to hash artifact: %w", err)
	}
	if n > maxArtifactBytes {
		return "", 0, fmt.Errorf("artifact exceeds maximum supported size (%d bytes)", maxArtifactBytes)
	}

	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readRegularNoFollow(path string, maxBytes int64) ([]byte, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	linfo, err := os.Lstat(absPath)
	if err != nil {
		return nil, err
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %q is a symbolic link", ErrSymlinkArtifact, filepath.Base(absPath))
	}
	if !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrNonRegularArtifact, filepath.Base(absPath))
	}

	root, err := os.OpenRoot(filepath.Dir(absPath))
	if err != nil {
		return nil, err
	}
	defer root.Close()

	f, err := openRegularNoFollow(root, filepath.Base(absPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum allowed size (%d bytes)", filepath.Base(absPath), maxBytes)
	}
	return data, nil
}

func writeReceiptSafely(outPath string, data []byte) error {
	if linfo, err := os.Lstat(outPath); err == nil {
		if linfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: output path %q is a symbolic link", ErrSymlinkArtifact, filepath.Base(outPath))
		}
		if linfo.IsDir() {
			return fmt.Errorf("%w: output path %q is a directory", ErrNonRegularArtifact, filepath.Base(outPath))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to inspect output path: %w", err)
	}

	parentDir := filepath.Dir(outPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	tmp, err := os.CreateTemp(parentDir, ".soulcaster-receipt-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary receipt file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write receipt: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync receipt: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close receipt: %w", err)
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		return fmt.Errorf("failed to set receipt permissions: %w", err)
	}

	// Re-check target immediately before rename to guard against symlink race
	if linfo, err := os.Lstat(outPath); err == nil && linfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: output path %q became a symbolic link", ErrSymlinkArtifact, filepath.Base(outPath))
	}

	if err := os.Rename(tmpName, outPath); err != nil {
		return fmt.Errorf("failed to move receipt into place: %w", err)
	}
	tmpName = ""
	return nil
}

func isSymlinkOpenErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "too many levels of symbolic links") ||
		strings.Contains(msg, "eloop") ||
		strings.Contains(msg, "symlink") ||
		strings.Contains(msg, "escapes from parent")
}

// collectLocalGitMetadata reads local git HEAD commit, branch, and dirty status
// strictly from the local filesystem with a short timeout and zero network calls.
func collectLocalGitMetadata(workDir string) GitMetadata {
	var meta GitMetadata
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if commit, err := runLocalGit(ctx, workDir, "rev-parse", "HEAD"); err == nil && isHexSHA(commit) {
		meta.Commit = commit
	} else {
		return meta
	}

	if branch, err := runLocalGit(ctx, workDir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && branch != "" {
		meta.Branch = ux.SanitizeTerminalText(branch)
	}

	if status, err := runLocalGit(ctx, workDir, "status", "--porcelain"); err == nil {
		meta.Dirty = strings.TrimSpace(status) != ""
	}

	return meta
}

func runLocalGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	// Prevent git from touching network or interactive prompts.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
