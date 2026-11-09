package astdiff

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	maxAnalyzedFileBytes = 32 << 20 // 32 MiB max single source file
	maxDiffBytes         = 64 << 20 // 64 MiB max git diff / patch stream
)

// LanguageAnalyzer is the interface implemented by language-specific AST engines.
type LanguageAnalyzer interface {
	Language() string
	CanAnalyze(filename string) bool
	AnalyzeSources(filename string, baseSource, headSource []byte, fileDiff *FileDiff) ([]Violation, error)
}

// Analyzer orchestrates differential AST security checks across supported languages.
type Analyzer struct {
	analyzers []LanguageAnalyzer
}

// NewAnalyzer creates an Analyzer initialized with Go, Python, and Rust support.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		analyzers: []LanguageAnalyzer{
			NewGoAnalyzer(),
			NewPythonAnalyzer(),
			NewRustAnalyzer(),
		},
	}
}

// RegisterAnalyzer adds or overrides a language analyzer.
func (a *Analyzer) RegisterAnalyzer(la LanguageAnalyzer) {
	a.analyzers = append(a.analyzers, la)
}

func (a *Analyzer) findAnalyzer(filename string) LanguageAnalyzer {
	for _, la := range a.analyzers {
		if la.CanAnalyze(filename) {
			return la
		}
	}
	return nil
}

// AnalyzeSources evaluates base and head source bytes for a single file.
func (a *Analyzer) AnalyzeSources(filename string, baseSource, headSource []byte) (*AnalysisResult, error) {
	if int64(len(baseSource)) > maxAnalyzedFileBytes || int64(len(headSource)) > maxAnalyzedFileBytes {
		return nil, fmt.Errorf("source input for %s exceeds %d byte limit", filename, maxAnalyzedFileBytes)
	}
	res := NewAnalysisResult("base", "head")
	res.Files = append(res.Files, filename)
	res.Summary.TotalFilesAnalyzed = 1

	la := a.findAnalyzer(filename)
	if la == nil {
		return res, nil
	}

	violations, err := la.AnalyzeSources(filename, baseSource, headSource, nil)
	if err != nil {
		return nil, fmt.Errorf("analysis error for %s: %w", filename, err)
	}

	for _, v := range violations {
		res.AddViolation(v)
	}

	return res, nil
}

// AnalyzeFilePair compares two files on disk with bounded reads.
func (a *Analyzer) AnalyzeFilePair(basePath, headPath string) (*AnalysisResult, error) {
	var baseBytes []byte
	var headBytes []byte
	var err error

	if basePath != "" {
		baseBytes, err = readBoundedFile(basePath, maxAnalyzedFileBytes)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read base file %s: %w", basePath, err)
		}
	}

	if headPath != "" {
		headBytes, err = readBoundedFile(headPath, maxAnalyzedFileBytes)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read head file %s: %w", headPath, err)
		}
	}

	evalName := headPath
	if evalName == "" {
		evalName = basePath
	}

	return a.AnalyzeSources(evalName, baseBytes, headBytes)
}

// AnalyzePatch parses and evaluates a unified diff/patch directly.
func (a *Analyzer) AnalyzePatch(patchData []byte) (*AnalysisResult, error) {
	if int64(len(patchData)) > maxDiffBytes {
		return nil, fmt.Errorf("patch payload exceeds %d byte limit", maxDiffBytes)
	}
	fileDiffs, err := ParsePatch(patchData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse patch data: %w", err)
	}

	res := NewAnalysisResult("patch-base", "patch-head")

	for _, fd := range fileDiffs {
		evalPath := fd.NewPath
		if evalPath == "" {
			evalPath = fd.OldPath
		}
		if evalPath == "" {
			continue
		}

		la := a.findAnalyzer(evalPath)
		if la == nil {
			continue
		}

		res.Files = append(res.Files, evalPath)
		res.Summary.TotalFilesAnalyzed++

		// Reconstruct base and head hunks safely; only read local disk if evalPath is a safe relative path.
		var headBytes []byte
		var baseBytes []byte
		if isSafeRelativePath(evalPath) {
			if data, err := readBoundedFile(evalPath, maxAnalyzedFileBytes); err == nil {
				headBytes = data
			}
		}

		if len(headBytes) == 0 {
			baseBytes, headBytes = reconstructSourcesFromDiff(fd)
		}

		violations, err := la.AnalyzeSources(evalPath, baseBytes, headBytes, fd)
		if err != nil {
			return nil, fmt.Errorf("failed to analyze diff for %s: %w", evalPath, err)
		}

		for _, v := range violations {
			res.AddViolation(v)
		}
	}

	return res, nil
}

// ValidateGitRef ensures a git revision cannot inject CLI flags or control characters into git commands.
func ValidateGitRef(ref string) error {
	if ref == "" {
		return errors.New("git ref cannot be empty")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("invalid git ref %q: refs starting with '-' are forbidden (flag injection guard)", ref)
	}
	if len(ref) > 256 {
		return fmt.Errorf("invalid git ref %q: exceeds 256 characters", ref)
	}
	for _, r := range ref {
		if r == 0 || unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("invalid git ref %q: contains whitespace or control characters", ref)
		}
	}
	return nil
}

// AnalyzeGitDiff extracts diff from git repository and evaluates using bounded git object contents.
func (a *Analyzer) AnalyzeGitDiff(repoDir, baseRef, headRef string) (*AnalysisResult, error) {
	if headRef == "" {
		headRef = "HEAD"
	}
	if err := ValidateGitRef(baseRef); err != nil {
		return nil, err
	}
	if err := ValidateGitRef(headRef); err != nil {
		return nil, err
	}

	absRepoDir, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repoDir %q: %w", repoDir, err)
	}

	// 1. Get raw diff safely with --no-ext-diff and -- separator.
	diffBytes, err := runBoundedCommand(absRepoDir, maxDiffBytes, "git", "diff", "--no-ext-diff", baseRef, headRef, "--")
	if err != nil {
		return nil, fmt.Errorf("git diff failed (%s..%s): %w", baseRef, headRef, err)
	}

	fileDiffs, err := ParsePatch(diffBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse git diff: %w", err)
	}

	res := NewAnalysisResult(baseRef, headRef)

	for _, fd := range fileDiffs {
		evalPath := fd.NewPath
		if evalPath == "" {
			evalPath = fd.OldPath
		}
		if evalPath == "" {
			continue
		}

		la := a.findAnalyzer(evalPath)
		if la == nil {
			continue
		}

		res.Files = append(res.Files, evalPath)
		res.Summary.TotalFilesAnalyzed++

		var baseBytes []byte
		if fd.OldPath != "" && !fd.IsNew && isSafeRelativePath(fd.OldPath) {
			out, showErr := runBoundedCommand(absRepoDir, maxAnalyzedFileBytes, "git", "show", fmt.Sprintf("%s:%s", baseRef, fd.OldPath))
			if showErr == nil {
				baseBytes = out
			}
		}

		var headBytes []byte
		if fd.NewPath != "" && !fd.IsDeleted && isSafeRelativePath(fd.NewPath) {
			out, showErr := runBoundedCommand(absRepoDir, maxAnalyzedFileBytes, "git", "show", fmt.Sprintf("%s:%s", headRef, fd.NewPath))
			if showErr == nil {
				headBytes = out
			} else {
				candidate := filepath.Join(absRepoDir, filepath.Clean(filepath.FromSlash(fd.NewPath)))
				if data, errRead := readBoundedFile(candidate, maxAnalyzedFileBytes); errRead == nil {
					headBytes = data
				}
			}
		}

		violations, err := la.AnalyzeSources(evalPath, baseBytes, headBytes, fd)
		if err != nil {
			return nil, fmt.Errorf("failed to analyze git diff for %s: %w", evalPath, err)
		}

		for _, v := range violations {
			res.AddViolation(v)
		}
	}

	return res, nil
}

// AnalyzeDirectories recursively compares two directory trees with bounded reads.
func (a *Analyzer) AnalyzeDirectories(baseDir, headDir string) (*AnalysisResult, error) {
	res := NewAnalysisResult(baseDir, headDir)

	err := filepath.Walk(headDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, err := filepath.Rel(headDir, path)
		if err != nil {
			return err
		}
		if !isSafeRelativePath(relPath) {
			return fmt.Errorf("unsafe relative path %q in directory walk", relPath)
		}

		la := a.findAnalyzer(relPath)
		if la == nil {
			return nil
		}

		res.Files = append(res.Files, relPath)
		res.Summary.TotalFilesAnalyzed++

		headBytes, err := readBoundedFile(path, maxAnalyzedFileBytes)
		if err != nil {
			return err
		}

		var baseBytes []byte
		basePath := filepath.Join(baseDir, relPath)
		if bData, err := readBoundedFile(basePath, maxAnalyzedFileBytes); err == nil {
			baseBytes = bData
		}

		violations, err := la.AnalyzeSources(relPath, baseBytes, headBytes, nil)
		if err != nil {
			return fmt.Errorf("failed to analyze %s: %w", relPath, err)
		}

		for _, v := range violations {
			res.AddViolation(v)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk head directory: %w", err)
	}

	return res, nil
}

func isSafeRelativePath(p string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	fromSlash := filepath.FromSlash(p)
	if filepath.IsAbs(fromSlash) {
		return false
	}
	clean := filepath.Clean(fromSlash)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
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
		return nil, fmt.Errorf("file %q exceeds %d byte read limit", path, maxBytes)
	}
	return data, nil
}

func runBoundedCommand(dir string, maxBytes int64, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	data, readErr := io.ReadAll(io.LimitReader(stdout, maxBytes+1))
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s output exceeded %d byte limit", name, maxBytes)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("%w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return data, nil
}

func reconstructSourcesFromDiff(fd *FileDiff) (base []byte, head []byte) {
	var baseBuf bytes.Buffer
	var headBuf bytes.Buffer

	for _, hunk := range fd.Hunks {
		for _, dl := range hunk.Lines {
			switch dl.Type {
			case LineContext:
				baseBuf.WriteString(dl.Content + "\n")
				headBuf.WriteString(dl.Content + "\n")
			case LineAdded:
				headBuf.WriteString(dl.Content + "\n")
			case LineRemoved:
				baseBuf.WriteString(dl.Content + "\n")
			}
		}
	}

	return baseBuf.Bytes(), headBuf.Bytes()
}
