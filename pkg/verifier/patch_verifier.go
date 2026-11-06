package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bonjoski/soulcaster/pkg/astdiff"
	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/bonjoski/soulcaster/pkg/version"
	"github.com/google/uuid"
)

// PatchVerificationOptions configures the secondary vulnerability gate.
type PatchVerificationOptions struct {
	BaseRef         string
	HeadRef         string
	BaseFile        string
	HeadFile        string
	BaseDir         string
	HeadDir         string
	PatchPath       string
	PatchBytes      []byte
	AttestationPath string
	WorkDir         string
	InvocationID    string
	Strict          bool
}

// PatchVerificationResult encapsulates the outcome of the secondary vulnerability CI gate.
type PatchVerificationResult struct {
	Passed          bool                           `json:"passed"`
	AttestationPath string                         `json:"attestationPath,omitempty"`
	Attestation     *intoto.SecondaryGateStatement `json:"attestation,omitempty"`
	Analysis        *astdiff.AnalysisResult        `json:"analysis"`
	DiagnosticJSON  string                         `json:"diagnosticJson,omitempty"`
	Summary         string                         `json:"summary"`
}

// VerifyPatch executes differential AST security checks on the patch/head vs base.
// On failure: fails closed, shreds any stale attestation, and produces machine-readable diagnostic proof.
// On success: emits an in-toto v1.0 Statement with predicate https://bonjoski.github.io/attestation/secondary-vulnerability-gate/v1.
func VerifyPatch(opts PatchVerificationOptions) (*PatchVerificationResult, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
	}

	analyzer := astdiff.NewAnalyzer()
	var analysis *astdiff.AnalysisResult
	var err error
	var subjectBytes []byte
	subjectName := "patch"

	if opts.PatchPath != "" {
		absPatch := opts.PatchPath
		if !filepath.IsAbs(absPatch) {
			absPatch = filepath.Join(workDir, opts.PatchPath)
		}
		data, errRead := os.ReadFile(absPatch)
		if errRead != nil {
			return nil, fmt.Errorf("failed to read patch file %s: %w", absPatch, errRead)
		}
		subjectBytes = data
		subjectName = filepath.Base(absPatch)
		analysis, err = analyzer.AnalyzePatch(data)
	} else if len(opts.PatchBytes) > 0 {
		subjectBytes = opts.PatchBytes
		analysis, err = analyzer.AnalyzePatch(opts.PatchBytes)
	} else if opts.BaseDir != "" && opts.HeadDir != "" {
		analysis, err = analyzer.AnalyzeDirectories(opts.BaseDir, opts.HeadDir)
		subjectName = filepath.Base(opts.HeadDir)
		subjectBytes = []byte(opts.HeadDir)
	} else if opts.BaseFile != "" || opts.HeadFile != "" {
		analysis, err = analyzer.AnalyzeFilePair(opts.BaseFile, opts.HeadFile)
		subjectName = filepath.Base(opts.HeadFile)
		if data, errRead := os.ReadFile(opts.HeadFile); errRead == nil {
			subjectBytes = data
		} else {
			subjectBytes = []byte(opts.HeadFile)
		}
	} else if opts.BaseRef != "" {
		analysis, err = analyzer.AnalyzeGitDiff(workDir, opts.BaseRef, opts.HeadRef)
		subjectName = fmt.Sprintf("git-diff-%s..%s", opts.BaseRef, opts.HeadRef)
		subjectBytes = []byte(fmt.Sprintf("%s..%s", opts.BaseRef, opts.HeadRef))
	} else {
		return nil, fmt.Errorf("no verification target specified: provide --patch, --base/--head files, --base-dir/--head-dir, or --base git ref")
	}

	if err != nil {
		return nil, fmt.Errorf("differential AST analysis failed: %w", err)
	}

	res := &PatchVerificationResult{
		Passed:   analysis.Passed,
		Analysis: analysis,
		Summary:  analysis.FormatDiagnosticReport(),
	}

	// Always produce machine-readable diagnostic proof
	diagBytes, _ := analysis.ToJSON()
	res.DiagnosticJSON = string(diagBytes)

	// Fail closed if any violations detected
	if !analysis.Passed {
		// Clean up stale attestation if path provided
		if opts.AttestationPath != "" {
			_ = os.Remove(opts.AttestationPath)
		}
		return res, nil
	}

	// Analysis passed: generate in-toto v1.0 Statement with Secondary Vulnerability Gate predicate
	if len(subjectBytes) == 0 {
		subjectBytes = []byte("empty-patch")
	}
	hash := sha256.Sum256(subjectBytes)
	subjDigest := hex.EncodeToString(hash[:])

	subjects := []intoto.ResourceDescriptor{
		{
			Name: subjectName,
			Digest: intoto.DigestSet{
				"sha256": subjDigest,
			},
		},
	}

	summary := intoto.GateChecksSummary{
		TotalFilesAnalyzed:        analysis.Summary.TotalFilesAnalyzed,
		TotalViolations:           analysis.Summary.TotalViolations,
		AuthBypassViolations:      analysis.Summary.AuthBypassViolations,
		ErrorSwallowingViolations: analysis.Summary.ErrorSwallowingViolations,
		DangerousMemoryViolations: analysis.Summary.DangerousMemoryViolations,
	}

	now := time.Now().UTC()
	invID := opts.InvocationID
	if invID == "" {
		invID = fmt.Sprintf("urn:uuid:%s", uuid.New().String())
	}

	stmt := intoto.NewSecondaryGateStatement(
		subjects,
		opts.BaseRef,
		opts.HeadRef,
		analysis.Files,
		true,
		summary,
		nil,
		version.Version,
		invID,
		&now,
		&now,
	)

	res.Attestation = stmt

	if opts.AttestationPath != "" {
		absAttest := opts.AttestationPath
		if !filepath.IsAbs(absAttest) {
			absAttest = filepath.Join(workDir, opts.AttestationPath)
		}
		if err := os.MkdirAll(filepath.Dir(absAttest), 0755); err != nil {
			return nil, fmt.Errorf("failed to create attestation directory: %w", err)
		}
		jsonlData, err := stmt.ToJSONL()
		if err != nil {
			return nil, fmt.Errorf("failed to format gate attestation: %w", err)
		}
		if err := os.WriteFile(absAttest, jsonlData, 0644); err != nil {
			return nil, fmt.Errorf("failed to write gate attestation to %s: %w", absAttest, err)
		}
		res.AttestationPath = absAttest
	}

	return res, nil
}

// VerifySecondaryGateAttestation reads and verifies an in-toto secondary gate statement.
func VerifySecondaryGateAttestation(attestationPath string) (*intoto.SecondaryGateStatement, error) {
	data, err := os.ReadFile(attestationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gate attestation %s: %w", attestationPath, err)
	}

	stmt, err := intoto.ParseSecondaryGateStatement(data)
	if err != nil {
		return nil, fmt.Errorf("gate attestation schema validation error: %w", err)
	}

	if stmt.Predicate.GateResult != intoto.GateResultPassed {
		return nil, fmt.Errorf("gate attestation indicates FAILED verification (total violations: %d)", stmt.Predicate.ChecksSummary.TotalViolations)
	}

	return stmt, nil
}
