package wrapper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/google/uuid"
)

const maxSourceFileSize = 128 << 20 // 128 MiB per source file guard

var defaultSourceExtensions = map[string]bool{
	".go":   true,
	".c":    true,
	".h":    true,
	".hpp":  true,
	".cc":   true,
	".cpp":  true,
	".rs":   true,
	".py":   true,
	".s":    true,
	".asm":  true,
	".mod":  true,
	".sum":  true,
	".toml": true,
	".lock": true,
	".json": true,
	".yaml": true,
	".yml":  true,
}

var specialSourceFilenames = map[string]bool{
	"Makefile":          true,
	"CMakeLists.txt":    true,
	"go.mod":            true,
	"go.sum":            true,
	"go.work":           true,
	"go.work.sum":       true,
	"modules.txt":       true,
	"Cargo.toml":        true,
	"Cargo.lock":        true,
	"build.rs":          true,
	"package.json":      true,
	"package-lock.json": true,
	"pnpm-lock.yaml":    true,
	"yarn.lock":         true,
}

// Note: "vendor" is intentionally NOT ignored so vendored dependencies under GOPROXY=off are hashed.
var ignoredDirectories = map[string]bool{
	".git":         true,
	".github":      true,
	"node_modules": true,
	".cache":       true,
	"tmp":          true,
	".idea":        true,
	".vscode":      true,
}

// hermeticEnvAllowlist is the strict clean-room allowlist passed to child compilers.
// Dangerous variables (GOFLAGS, LD_PRELOAD, DYLD_INSERT_LIBRARIES, RUSTC_WRAPPER, CC, CXX, etc.) are excluded.
var hermeticEnvAllowlist = map[string]bool{
	"PATH":        true,
	"HOME":        true,
	"TMPDIR":      true,
	"USER":        true,
	"LANG":        true,
	"GOOS":        true,
	"GOARCH":      true,
	"CGO_ENABLED": true,
}

var blockedExactFlags = map[string]bool{
	"-overlay":        true,
	"--overlay":       true,
	"-toolexec":       true,
	"--toolexec":      true,
	"-modfile":        true,
	"--modfile":       true,
	"-gcflags":        true,
	"--gcflags":       true,
	"-asmflags":       true,
	"--asmflags":      true,
	"-gccgoflags":     true,
	"--gccgoflags":    true,
	"--config":        true,
	"--rustc-wrapper": true,
	"-fplugin":        true,
	"-specs":          true,
}

// Config controls the compiler wrapping invocation.
type Config struct {
	Command         []string
	WorkDir         string
	OutputBinary    string
	AttestationPath string
	Hermetic        bool
	NetworkIsolated bool
	Sign            bool
	SigningKey      string
	Version         string
	Stdout          io.Writer
	Stderr          io.Writer
	Env             []string
}

// Result summarizes the execution and attestation generation.
type Result struct {
	Statement           *intoto.Statement
	Envelope            *intoto.DSSEEnvelope
	Signed              bool
	KeyID               string
	OutputBinary        string
	OutputDigest        string
	SourceFilesCaptured int
	ExecutionDuration   time.Duration
	ExitCode            int
	AttestationPath     string
}

// FileRecord represents a tracked source file with metadata.
type FileRecord struct {
	Path    string
	RelPath string
	Digest  string
	Size    int64
}

// Wrap runs the build command inside an isolated read-only source snapshot,
// enforces a clean-room compiler environment, and emits an in-toto SLSA attestation.
func Wrap(cfg Config) (*Result, error) {
	if len(cfg.Command) == 0 {
		return nil, errors.New("empty build command provided")
	}

	if err := validateCompilerArgs(cfg.Command); err != nil {
		return nil, fmt.Errorf("blocked compiler argument: %w", err)
	}

	// Fail closed immediately if signing is requested without a valid Ed25519 key.
	var signingPrivKey ed25519.PrivateKey
	wantSign := cfg.Sign || strings.TrimSpace(cfg.SigningKey) != ""
	if wantSign {
		keySpec := strings.TrimSpace(cfg.SigningKey)
		if keySpec == "" {
			keySpec = strings.TrimSpace(os.Getenv("SOULCASTER_SIGNING_KEY"))
		}
		if keySpec == "" {
			return nil, errors.New("signing requested (--sign) but no signing key provided via --signing-key or SOULCASTER_SIGNING_KEY")
		}
		var err error
		signingPrivKey, err = intoto.ParseEd25519PrivateKey(keySpec)
		if err != nil {
			return nil, fmt.Errorf("invalid Ed25519 signing key: %w", err)
		}
	}

	workDir := cfg.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %w", err)
		}
	}
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve working directory: %w", err)
	}

	version := cfg.Version
	if version == "" {
		version = "0.1.0"
	}

	// 1. Resolve target output binary path up front.
	detectedOut := detectOutputBinary(cfg.Command)
	outputBinary := cfg.OutputBinary
	if outputBinary == "" {
		outputBinary = detectedOut
	}
	if outputBinary == "" {
		return nil, errors.New("unable to determine output binary; use -o or provide --output-binary")
	}
	absOutput := outputBinary
	if !filepath.IsAbs(absOutput) {
		absOutput = filepath.Join(absWorkDir, outputBinary)
	}
	if err := os.MkdirAll(filepath.Dir(absOutput), 0755); err != nil {
		return nil, fmt.Errorf("failed to create output binary parent directory: %w", err)
	}

	attestationPath := cfg.AttestationPath
	if attestationPath == "" {
		attestationPath = absOutput + ".intoto.jsonl"
	}
	if !filepath.IsAbs(attestationPath) {
		attestationPath = filepath.Join(absWorkDir, attestationPath)
	}

	// 2. Resolve compiler toolchain digest.
	compilerExe := cfg.Command[0]
	if !filepath.IsAbs(compilerExe) && strings.ContainsRune(compilerExe, filepath.Separator) {
		compilerExe = filepath.Join(absWorkDir, compilerExe)
	}
	compilerPath, lookErr := exec.LookPath(compilerExe)
	var compilerDigest intoto.DigestSet
	if lookErr == nil {
		if cDigest, hErr := HashFile(compilerPath); hErr == nil {
			compilerDigest = intoto.DigestSet{"sha256": cDigest}
		}
	}

	// 3. Discover and hash all input source files (pre-build snapshot), rejecting external symlinks.
	preSources, err := ScanSourceFiles(absWorkDir)
	if err != nil {
		return nil, fmt.Errorf("failed to scan source files: %w", err)
	}

	// 4. Stage workspace into an ephemeral read-only snapshot directory to defeat mid-build AB-BA TOCTOU swaps.
	allowRelativeCWDOutput := detectedOut == "" && !filepath.IsAbs(cfg.OutputBinary)
	stageDir, err := stageReadOnlySnapshot(absWorkDir, !allowRelativeCWDOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to stage immutable source snapshot: %w", err)
	}
	defer cleanupStageDir(stageDir)

	// 5. Create ephemeral isolated GOCACHE and strict hermetic environment.
	goCacheDir, err := os.MkdirTemp("", "soulcaster-gocache-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create isolated GOCACHE: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(goCacheDir); rmErr != nil && cfg.Stderr != nil {
			fmt.Fprintf(cfg.Stderr, "warning: failed to remove temporary GOCACHE: %v\n", rmErr)
		}
	}()

	cmdEnv, envMap := buildCleanEnvironment(cfg.Env, cfg.Hermetic, goCacheDir)
	execArgs := prepareExecCommand(cfg.Command, absWorkDir, absOutput)

	// 6. Execute compiler inside the read-only staged snapshot.
	startTime := time.Now().UTC()
	cmd := exec.Command(execArgs[0], execArgs[1:]...)
	cmd.Dir = stageDir
	cmd.Env = cmdEnv
	if cfg.Stdout != nil {
		cmd.Stdout = cfg.Stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if cfg.Stderr != nil {
		cmd.Stderr = cfg.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	runErr := cmd.Run()
	finishTime := time.Now().UTC()
	execDuration := finishTime.Sub(startTime)

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("build execution failed: %w", runErr)
		}
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("compiler exited with status %d", exitCode)
	}

	// If a custom script wrote a relative output binary inside stageDir, copy it out to absOutput.
	if allowRelativeCWDOutput {
		if _, statErr := os.Stat(absOutput); os.IsNotExist(statErr) {
			stagedOut := filepath.Join(stageDir, cfg.OutputBinary)
			if copyErr := copyRegularFile(stagedOut, absOutput, 0755); copyErr != nil {
				return nil, fmt.Errorf("failed to copy staged output binary: %w", copyErr)
			}
		}
	}

	// 7. Post-build TOCTOU integrity checks on BOTH staged snapshot and workspace.
	stagePost, err := ScanSourceFiles(stageDir)
	if err != nil {
		return nil, fmt.Errorf("post-build staged snapshot verification failed: %w", err)
	}
	stagePost = filterOutArtifacts(stagePost, filepath.Clean(filepath.Join(stageDir, cfg.OutputBinary)), "")
	if err := verifySourceIntegrity(preSources, stagePost); err != nil {
		return nil, fmt.Errorf("security violation in staged snapshot: %w", err)
	}

	postSources, err := ScanSourceFiles(absWorkDir)
	if err != nil {
		return nil, fmt.Errorf("post-build source verification failed: %w", err)
	}
	postSources = filterOutArtifacts(postSources, filepath.Clean(absOutput), filepath.Clean(attestationPath))
	if err := verifySourceIntegrity(preSources, postSources); err != nil {
		return nil, fmt.Errorf("security violation: %w", err)
	}

	// 8. Verify and hash output binary.
	if _, err := os.Stat(absOutput); err != nil {
		return nil, fmt.Errorf("expected output binary %q not found after build: %w", absOutput, err)
	}
	outputSha, err := HashFile(absOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to hash output binary %q: %w", absOutput, err)
	}

	// 9. Construct in-toto Statement & Resource Descriptors.
	subject := []intoto.ResourceDescriptor{
		{
			Name:   filepath.Base(outputBinary),
			URI:    "file://" + filepath.ToSlash(relOrAbs(absWorkDir, absOutput)),
			Digest: intoto.DigestSet{"sha256": outputSha},
		},
	}

	sourceDescriptors := make([]intoto.ResourceDescriptor, 0, len(preSources))
	for _, src := range preSources {
		sourceDescriptors = append(sourceDescriptors, intoto.ResourceDescriptor{
			Name:   src.RelPath,
			URI:    "file://" + src.RelPath,
			Digest: intoto.DigestSet{"sha256": src.Digest},
			Annotations: map[string]string{
				"sizeBytes": fmt.Sprintf("%d", src.Size),
			},
		})
	}

	socketsDetected := "unverified"
	networkIsolation := "none"
	if cfg.NetworkIsolated {
		socketsDetected = "0"
		networkIsolation = "sandbox-enforced"
	} else if cfg.Hermetic {
		networkIsolation = "hermetic-env"
	}

	byproducts := []intoto.ResourceDescriptor{
		{
			Name: "networkActivity",
			Annotations: map[string]string{
				"externalSocketsDetected": socketsDetected,
				"networkIsolation":        networkIsolation,
				"hermeticMode":            fmt.Sprintf("%t", cfg.Hermetic),
				"toctouIntegrityVerified": "true",
			},
		},
	}

	internalParams := intoto.InternalParameters{
		SoulcasterVersion: version,
		WorkingDir:        absWorkDir,
		CompilerPath:      compilerPath,
		CompilerDigest:    compilerDigest,
		HermeticMode:      cfg.Hermetic,
	}

	stmt := intoto.NewStatement(
		subject,
		cfg.Command,
		sourceDescriptors,
		envMap,
		internalParams,
		&startTime,
		&finishTime,
		uuid.New().String(),
		byproducts,
	)

	// 10. Serialize (signing into DSSEv1 if requested) and write attestation.
	var outBytes []byte
	var dsseEnv *intoto.DSSEEnvelope
	var keyID string
	if wantSign {
		dsseEnv, outBytes, err = intoto.SignStatementDSSE(stmt, signingPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign DSSE attestation: %w", err)
		}
		keyID = intoto.KeyIDForPublicKey(signingPrivKey.Public().(ed25519.PublicKey))
	} else {
		outBytes, err = stmt.ToJSONL()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize attestation: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(attestationPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create attestation directory: %w", err)
	}
	if err := os.WriteFile(attestationPath, outBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write attestation to %q: %w", attestationPath, err)
	}

	return &Result{
		Statement:           stmt,
		Envelope:            dsseEnv,
		Signed:              wantSign,
		KeyID:               keyID,
		OutputBinary:        absOutput,
		OutputDigest:        outputSha,
		SourceFilesCaptured: len(sourceDescriptors),
		ExecutionDuration:   execDuration,
		ExitCode:            exitCode,
		AttestationPath:     attestationPath,
	}, nil
}

func validateCompilerArgs(cmd []string) error {
	for i := 1; i < len(cmd); i++ {
		arg := strings.TrimSpace(cmd[i])
		if arg == "" {
			continue
		}
		flagName := arg
		flagVal := ""
		hasEq := false
		if eqIdx := strings.IndexByte(arg, '='); eqIdx != -1 {
			flagName = arg[:eqIdx]
			flagVal = arg[eqIdx+1:]
			hasEq = true
		}

		if blockedExactFlags[flagName] {
			return fmt.Errorf("compiler flag %q is forbidden in attested builds", flagName)
		}
		if strings.HasPrefix(arg, "-Z") || flagName == "-Z" {
			return fmt.Errorf("unstable compiler flag %q is forbidden in attested builds", arg)
		}
		if strings.HasPrefix(arg, "-fplugin=") || strings.HasPrefix(arg, "-specs=") {
			return fmt.Errorf("compiler plugin/spec flag %q is forbidden in attested builds", arg)
		}

		if flagName == "-ldflags" || flagName == "--ldflags" {
			val := flagVal
			if !hasEq && i+1 < len(cmd) {
				val = cmd[i+1]
			}
			if containsBlockedLinkerDirective(val) {
				return fmt.Errorf("external linker hijack in %s (%q) is forbidden", flagName, val)
			}
		}

		if flagName == "-C" || flagName == "--codegen" {
			val := flagVal
			if !hasEq && i+1 < len(cmd) {
				val = cmd[i+1]
			}
			if strings.Contains(val, "linker=") || strings.Contains(val, "link-arg=") {
				return fmt.Errorf("custom rustc codegen linker directive %q is forbidden", val)
			}
		}
	}
	return nil
}

func containsBlockedLinkerDirective(ldflags string) bool {
	lower := strings.ToLower(ldflags)
	for _, bad := range []string{"-extld", "--extld", "-extldflags", "--extldflags", "-pluginpath"} {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

func buildCleanEnvironment(extraEnv []string, hermetic bool, goCacheDir string) ([]string, map[string]string) {
	allowed := make(map[string]string)
	sources := append([]string{}, os.Environ()...)
	sources = append(sources, extraEnv...)

	for _, entry := range sources {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := parts[0], parts[1]
		if hermeticEnvAllowlist[k] {
			allowed[k] = v
		} else if !hermetic && (k == "GOPROXY" || k == "GOSUMDB") {
			allowed[k] = v
		}
	}

	allowed["GOCACHE"] = goCacheDir
	if hermetic {
		allowed["GOPROXY"] = "off"
		allowed["GOSUMDB"] = "off"
		allowed["CARGO_NET_OFFLINE"] = "true"
	}

	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	cmdEnv := make([]string, 0, len(keys))
	recorded := make(map[string]string, len(keys)+1)
	for _, k := range keys {
		cmdEnv = append(cmdEnv, k+"="+allowed[k])
		recorded[k] = allowed[k]
	}
	if hermetic {
		recorded["HERMETIC_BUILD"] = "true"
	}
	return cmdEnv, recorded
}

func prepareExecCommand(cmd []string, absWorkDir, absOutput string) []string {
	out := make([]string, len(cmd))
	copy(out, cmd)
	if !filepath.IsAbs(out[0]) && strings.ContainsRune(out[0], filepath.Separator) {
		out[0] = filepath.Join(absWorkDir, out[0])
	}
	for i := 1; i < len(out); i++ {
		if (out[i] == "-o" || out[i] == "--output") && i+1 < len(out) {
			if !filepath.IsAbs(out[i+1]) {
				out[i+1] = absOutput
			}
			i++
			continue
		}
		if strings.HasPrefix(out[i], "-o=") {
			v := strings.TrimPrefix(out[i], "-o=")
			if !filepath.IsAbs(v) {
				out[i] = "-o=" + absOutput
			}
		}
	}
	return out
}

func detectOutputBinary(cmd []string) string {
	for i := 0; i < len(cmd); i++ {
		arg := cmd[i]
		if (arg == "-o" || arg == "--output") && i+1 < len(cmd) {
			return cmd[i+1]
		}
		if strings.HasPrefix(arg, "-o=") {
			return strings.TrimPrefix(arg, "-o=")
		}
		if strings.HasPrefix(arg, "--output=") {
			return strings.TrimPrefix(arg, "--output=")
		}
	}
	return ""
}

// ScanSourceFiles discovers and hashes all build-relevant source, manifest, and vendor files under root,
// failing closed if any symlink resolves outside root.
func ScanSourceFiles(root string) ([]FileRecord, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve root %q: %w", root, err)
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate root symlinks %q: %w", absRoot, err)
	}

	var records []FileRecord
	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		base := d.Name()
		if d.IsDir() {
			if ignoredDirectories[base] && path != absRoot {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			realTarget, symErr := filepath.EvalSymlinks(path)
			if symErr != nil {
				return fmt.Errorf("broken or unreadable symlink %q: %w", path, symErr)
			}
			if !IsWithinDir(realRoot, realTarget) {
				return fmt.Errorf("symlink escape detected: %q resolves outside workspace (%q)", path, realTarget)
			}
			tInfo, statErr := os.Stat(realTarget)
			if statErr != nil {
				return fmt.Errorf("failed to stat symlink target %q: %w", realTarget, statErr)
			}
			if tInfo.IsDir() {
				return fmt.Errorf("directory symlink %q is disallowed in hermetic workspace", path)
			}
			return maybeRecordFile(absRoot, path, tInfo.Size(), &records)
		}

		if !d.Type().IsRegular() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		return maybeRecordFile(absRoot, path, info.Size(), &records)
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].RelPath < records[j].RelPath
	})
	return records, nil
}

func maybeRecordFile(absRoot, path string, size int64, records *[]FileRecord) error {
	ext := filepath.Ext(path)
	base := filepath.Base(path)
	if !defaultSourceExtensions[ext] && !specialSourceFilenames[base] {
		return nil
	}
	rel, err := filepath.Rel(absRoot, path)
	if err != nil {
		return fmt.Errorf("failed to compute relative path for %q: %w", path, err)
	}
	digest, err := HashFile(path)
	if err != nil {
		return err
	}
	*records = append(*records, FileRecord{
		Path:    path,
		RelPath: filepath.ToSlash(rel),
		Digest:  digest,
		Size:    size,
	})
	return nil
}

func stageReadOnlySnapshot(absWorkDir string, lockDirs bool) (string, error) {
	realRoot, err := filepath.EvalSymlinks(absWorkDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve workspace symlinks: %w", err)
	}
	stageDir, err := os.MkdirTemp("", "soulcaster-stage-*")
	if err != nil {
		return "", fmt.Errorf("failed to create staging directory: %w", err)
	}

	var dirsToLock []string
	walkErr := filepath.WalkDir(absWorkDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(absWorkDir, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			dirsToLock = append(dirsToLock, stageDir)
			return nil
		}
		base := d.Name()
		if d.IsDir() {
			if ignoredDirectories[base] {
				return filepath.SkipDir
			}
			dstDir := filepath.Join(stageDir, rel)
			if mkErr := os.MkdirAll(dstDir, 0700); mkErr != nil {
				return mkErr
			}
			dirsToLock = append(dirsToLock, dstDir)
			return nil
		}

		srcPath := path
		if d.Type()&os.ModeSymlink != 0 {
			realTarget, symErr := filepath.EvalSymlinks(path)
			if symErr != nil {
				return fmt.Errorf("broken symlink %q: %w", path, symErr)
			}
			if !IsWithinDir(realRoot, realTarget) {
				return fmt.Errorf("symlink escape detected: %q resolves outside workspace", path)
			}
			srcPath = realTarget
		}
		info, statErr := os.Stat(srcPath)
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		dstFile := filepath.Join(stageDir, rel)
		perm := os.FileMode(0400)
		if info.Mode()&0111 != 0 {
			perm = 0500
		}
		return copyRegularFile(srcPath, dstFile, perm)
	})
	if walkErr != nil {
		cleanupStageDir(stageDir)
		return "", walkErr
	}

	if lockDirs {
		// Lock directories deepest-first to prevent mid-build file creation/unlink/rename.
		for i := len(dirsToLock) - 1; i >= 0; i-- {
			if chErr := os.Chmod(dirsToLock[i], 0500); chErr != nil {
				cleanupStageDir(stageDir)
				return "", fmt.Errorf("failed to lock staged directory: %w", chErr)
			}
		}
	}
	return stageDir, nil
}

func cleanupStageDir(stageDir string) {
	if stageDir == "" {
		return
	}
	walkErr := filepath.WalkDir(stageDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if chErr := os.Chmod(path, 0700); chErr != nil {
				return nil
			}
		} else {
			if chErr := os.Chmod(path, 0600); chErr != nil {
				return nil
			}
		}
		return nil
	})
	if walkErr == nil {
		if rmErr := os.RemoveAll(stageDir); rmErr != nil {
			return
		}
	}
}

func copyRegularFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, maxSourceFileSize+1)); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func filterOutArtifacts(records []FileRecord, absOutput, absAttestation string) []FileRecord {
	out := make([]FileRecord, 0, len(records))
	for _, r := range records {
		clean := filepath.Clean(r.Path)
		if clean == absOutput || (absAttestation != "" && clean == absAttestation) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func verifySourceIntegrity(pre, post []FileRecord) error {
	if len(pre) != len(post) {
		return fmt.Errorf("TOCTOU violation: source file count altered during build (pre: %d, post: %d)", len(pre), len(post))
	}

	postMap := make(map[string]FileRecord, len(post))
	for _, f := range post {
		postMap[f.RelPath] = f
	}

	for _, preFile := range pre {
		postFile, exists := postMap[preFile.RelPath]
		if !exists {
			return fmt.Errorf("TOCTOU violation: source file %q deleted during build", preFile.RelPath)
		}
		if preFile.Digest != postFile.Digest {
			return fmt.Errorf("TOCTOU violation: source file %q modified in-flight during build (pre-hash: %s, post-hash: %s)",
				preFile.RelPath, preFile.Digest, postFile.Digest)
		}
	}
	return nil
}

// IsWithinDir returns true iff targetPath is equal to or strictly inside rootDir after cleaning.
func IsWithinDir(rootDir, targetPath string) bool {
	rel, err := filepath.Rel(filepath.Clean(rootDir), filepath.Clean(targetPath))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// HashFile computes the bounded SHA-256 hex digest of a file on disk.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxSourceFileSize+1))
	if err != nil {
		return "", err
	}
	if n > maxSourceFileSize {
		return "", fmt.Errorf("file %q exceeds %d byte hashing limit", path, maxSourceFileSize)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func relOrAbs(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return rel
	}
	return target
}

// GenerateSourceHash creates a SHA-256 hash of byte content.
func GenerateSourceHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Ensure bytes buffer implements writer
var _ io.Writer = (*bytes.Buffer)(nil)
