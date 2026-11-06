package astdiff

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	res := NewAnalysisResult("base", "head")
	res.Files = append(res.Files, filename)
	res.Summary.TotalFilesAnalyzed = 1

	la := a.findAnalyzer(filename)
	if la == nil {
		// Not a supported language file; passes cleanly
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

// AnalyzeFilePair compares two files on disk.
func (a *Analyzer) AnalyzeFilePair(basePath, headPath string) (*AnalysisResult, error) {
	var baseBytes []byte
	var headBytes []byte
	var err error

	if basePath != "" {
		baseBytes, err = os.ReadFile(basePath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read base file %s: %w", basePath, err)
		}
	}

	if headPath != "" {
		headBytes, err = os.ReadFile(headPath)
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

		// If the file exists on disk, read current file
		var headBytes []byte
		var baseBytes []byte
		if data, err := os.ReadFile(evalPath); err == nil {
			headBytes = data
		}

		// Reconstruct base and head hunks from patch if disk read is unavailable
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

// AnalyzeGitDiff extracts diff from git repository and evaluates using full git object contents.
func (a *Analyzer) AnalyzeGitDiff(repoDir, baseRef, headRef string) (*AnalysisResult, error) {
	if headRef == "" {
		headRef = "HEAD"
	}

	// 1. Get raw diff
	args := []string{"diff", baseRef, headRef}
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	diffBytes, err := cmd.Output()
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

		// Fetch base content via git show
		var baseBytes []byte
		if fd.OldPath != "" && !fd.IsNew {
			showCmd := exec.Command("git", "show", fmt.Sprintf("%s:%s", baseRef, fd.OldPath))
			showCmd.Dir = repoDir
			out, err := showCmd.Output()
			if err == nil {
				baseBytes = out
			}
		}

		// Fetch head content via git show
		var headBytes []byte
		if fd.NewPath != "" && !fd.IsDeleted {
			showCmd := exec.Command("git", "show", fmt.Sprintf("%s:%s", headRef, fd.NewPath))
			showCmd.Dir = repoDir
			out, err := showCmd.Output()
			if err == nil {
				headBytes = out
			} else {
				// Fallback to local working directory if headRef is working tree
				if data, errRead := os.ReadFile(filepath.Join(repoDir, fd.NewPath)); errRead == nil {
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

// AnalyzeDirectories recursively compares two directory trees.
func (a *Analyzer) AnalyzeDirectories(baseDir, headDir string) (*AnalysisResult, error) {
	res := NewAnalysisResult(baseDir, headDir)

	headFiles := make(map[string]bool)

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

		la := a.findAnalyzer(relPath)
		if la == nil {
			return nil
		}

		headFiles[relPath] = true
		res.Files = append(res.Files, relPath)
		res.Summary.TotalFilesAnalyzed++

		headBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var baseBytes []byte
		basePath := filepath.Join(baseDir, relPath)
		if bData, err := os.ReadFile(basePath); err == nil {
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
