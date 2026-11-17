package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/soulcaster/pkg/astdiff"
	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/bonjoski/soulcaster/pkg/version"
	"github.com/google/uuid"
)

// VariantVerificationOptions configures the variant-hunting verification gate.
type VariantVerificationOptions struct {
	DiffPath        string
	DiffBytes       []byte
	TargetBinary    string
	BaselineBinary  string
	TestCmd         string
	AttestationPath string
	WorkDir         string
	InvocationID    string
}

// VariantVerificationResult encapsulates the outcome of the variant verification gate.
type VariantVerificationResult struct {
	Passed          bool                         `json:"passed"`
	AttestationPath string                       `json:"attestationPath,omitempty"`
	Attestation     *intoto.VariantGateStatement `json:"attestation,omitempty"`
	VariantResult   *astdiff.VariantHunterResult `json:"variantResult"`
	HardeningResult *HardeningReport             `json:"hardeningResult,omitempty"`
	DiagnosticJSON  string                       `json:"diagnosticJson,omitempty"`
	Summary         string                       `json:"summary"`
}

// VerifyVariant executes the variant-hunting verification gate:
// 1. Analyzes patch diff for newly introduced sanitizers, replacements, regexes, and branch conditions.
// 2. Probes for PatchSlop (incomplete quote stripping) and CFG adjacent branch bypasses.
// 3. Generates adversarial variant mutations across encodings, double URL encoding, unicode homoglyphs, overlong UTF-8, and null bytes.
// 4. Optionally executes test command against generated variants.
// 5. Optionally verifies ELF compiler hardening invariants on target binary.
// 6. If all checks pass with 0 bypasses and defenses intact, generates and writes an in-toto variant-gate statement.
func VerifyVariant(opts VariantVerificationOptions) (*VariantVerificationResult, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
	}

	var diffBytes []byte
	var diffName string

	if opts.DiffPath != "" {
		absDiff := opts.DiffPath
		if !filepath.IsAbs(absDiff) {
			absDiff = filepath.Join(workDir, opts.DiffPath)
		}
		data, err := os.ReadFile(absDiff)
		if err != nil {
			return nil, fmt.Errorf("failed to read diff file %s: %w", absDiff, err)
		}
		diffBytes = data
		diffName = filepath.Base(absDiff)
	} else if len(opts.DiffBytes) > 0 {
		diffBytes = opts.DiffBytes
		diffName = "patch.diff"
	} else {
		return nil, fmt.Errorf("no diff input specified: provide --diff <path>")
	}

	// 1. Differential AST variant analysis & mutation generation
	varResult, err := astdiff.AnalyzePatchVariants(diffBytes)
	if err != nil {
		return nil, fmt.Errorf("variant AST analysis failed: %w", err)
	}

	// 2. Execute test command against generated adversarial variants if specified
	if opts.TestCmd != "" {
		runTestCommandVariants(opts.TestCmd, workDir, varResult)
	}

	// 3. Inspect target binary hardening invariants if provided
	var hardReport *HardeningReport
	if opts.TargetBinary != "" {
		absBinary := opts.TargetBinary
		if !filepath.IsAbs(absBinary) {
			absBinary = filepath.Join(workDir, opts.TargetBinary)
		}

		if opts.BaselineBinary != "" {
			absBaseline := opts.BaselineBinary
			if !filepath.IsAbs(absBaseline) {
				absBaseline = filepath.Join(workDir, opts.BaselineBinary)
			}
			hardReport, err = CompareELFHardening(absBaseline, absBinary)
		} else {
			hardReport, err = VerifyELFHardeningInvariants(absBinary)
		}

		if err != nil {
			varResult.Passed = false
			for _, viol := range hardReport.Violations {
				varResult.Violations = append(varResult.Violations, astdiff.Violation{
					RuleID:   "SEC-BIN-001",
					RuleName: "CompilerDefenseAblated",
					Severity: astdiff.SeverityCritical,
					File:     absBinary,
					Message:  viol,
				})
			}
		}
	}

	// 4. Synthesize overall gate result
	gatePassed := varResult.Passed
	if hardReport != nil && !hardReport.DefensesIntact {
		gatePassed = false
	}

	res := &VariantVerificationResult{
		Passed:          gatePassed,
		VariantResult:   varResult,
		HardeningResult: hardReport,
		Summary:         buildVerificationSummary(varResult, hardReport, gatePassed),
	}

	// Generate machine-readable JSON diagnostic proof
	jsonBytes, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		res.DiagnosticJSON = string(jsonBytes)
	}

	// If failed, shred any stale attestation and return
	if !gatePassed {
		if opts.AttestationPath != "" {
			_ = os.Remove(opts.AttestationPath)
		}
		return res, nil
	}

	// 5. All variant fuzzing passed with 0 bypasses and defenses intact: emit in-toto statement assertion
	diffHash := sha256.Sum256(diffBytes)
	diffDigestHex := hex.EncodeToString(diffHash[:])

	subjects := []intoto.ResourceDescriptor{
		{
			Name: diffName,
			Digest: intoto.DigestSet{
				"sha256": diffDigestHex,
			},
		},
	}

	targetBinaryDigest := ""
	if opts.TargetBinary != "" {
		if binBytes, readErr := os.ReadFile(opts.TargetBinary); readErr == nil {
			binHash := sha256.Sum256(binBytes)
			targetBinaryDigest = hex.EncodeToString(binHash[:])
			subjects = append(subjects, intoto.ResourceDescriptor{
				Name: filepath.Base(opts.TargetBinary),
				Digest: intoto.DigestSet{
					"sha256": targetBinaryDigest,
				},
			})
		}
	}

	var encodingCount, unicodeCount, overlongCount, nullCount int
	for _, m := range varResult.Mutations {
		switch m.Category {
		case astdiff.MutationQuoteSubstitution, astdiff.MutationDoubleURLEncoding:
			encodingCount++
		case astdiff.MutationUnicodeFullwidth:
			unicodeCount++
		case astdiff.MutationOverlongUTF8:
			overlongCount++
		case astdiff.MutationNullByteInjection:
			nullCount++
		}
	}

	summary := intoto.VariantGateSummary{
		TotalVariantsGenerated:   varResult.TotalVariants,
		BypassesDetected:         varResult.BypassesDetected,
		EncodingVariants:         encodingCount,
		UnicodeVariants:          unicodeCount,
		OverlongVariants:         overlongCount,
		NullByteVariants:         nullCount,
		AdjacentBranchBypasses:   len(varResult.AdjacentBypasses),
		CompilerDefensesVerified: hardReport != nil,
		CompilerDefensesIntact:   hardReport == nil || hardReport.DefensesIntact,
	}

	invID := opts.InvocationID
	if invID == "" {
		invID = fmt.Sprintf("urn:uuid:%s", uuid.New().String())
	}
	now := time.Now().UTC()

	var diagProofs []intoto.VariantDiagnosticProof
	for _, v := range varResult.Violations {
		diagProofs = append(diagProofs, intoto.VariantDiagnosticProof{
			RuleID:   string(v.RuleID),
			RuleName: v.RuleName,
			Severity: string(v.Severity),
			File:     v.File,
			Line:     v.Line,
			Message:  v.Message,
		})
	}

	stmt := intoto.NewVariantGateStatement(
		subjects,
		diffName,
		diffDigestHex,
		opts.TargetBinary,
		targetBinaryDigest,
		true,
		summary,
		diagProofs,
		version.Version,
		invID,
		&now,
		&now,
	)

	res.Attestation = stmt

	// Write attestation file if requested or default
	attestPath := opts.AttestationPath
	if attestPath == "" && opts.DiffPath != "" {
		attestPath = opts.DiffPath + ".variant.intoto.jsonl"
	}

	if attestPath != "" {
		if !filepath.IsAbs(attestPath) {
			attestPath = filepath.Join(workDir, attestPath)
		}
		if err := os.MkdirAll(filepath.Dir(attestPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create attestation directory: %w", err)
		}
		jsonlData, err := stmt.ToJSONL()
		if err != nil {
			return nil, fmt.Errorf("failed to encode variant gate attestation: %w", err)
		}
		if err := os.WriteFile(attestPath, jsonlData, 0644); err != nil {
			return nil, fmt.Errorf("failed to write variant gate attestation to %s: %w", attestPath, err)
		}
		res.AttestationPath = attestPath
	}

	return res, nil
}

func runTestCommandVariants(testCmd, workDir string, varResult *astdiff.VariantHunterResult) {
	for _, mutation := range varResult.Mutations {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "sh", "-c", testCmd)
		cmd.Dir = workDir
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("SOULCASTER_VARIANT_PAYLOAD=%s", mutation.Payload),
			fmt.Sprintf("SOULCASTER_VARIANT_TARGET=%s", mutation.Target),
			fmt.Sprintf("SOULCASTER_VARIANT_CATEGORY=%s", mutation.Category),
		)
		cmd.Stdin = strings.NewReader(mutation.Payload)

		out, err := cmd.CombinedOutput()
		cancel()

		if err != nil {
			varResult.Passed = false
			varResult.BypassesDetected++
			varResult.Violations = append(varResult.Violations, astdiff.Violation{
				RuleID:   astdiff.RuleEncodingBypass,
				RuleName: "VariantTestExecutionFailure",
				Severity: astdiff.SeverityCritical,
				Message:  fmt.Sprintf("Adversarial mutation %s (%s) triggered test failure / bypass: %v. Output: %s", mutation.Category, mutation.Payload, err, strings.TrimSpace(string(out))),
				Metadata: map[string]string{
					"payload":  mutation.Payload,
					"category": string(mutation.Category),
				},
			})
		}
	}
}

func buildVerificationSummary(vRes *astdiff.VariantHunterResult, hRes *HardeningReport, passed bool) string {
	var sb strings.Builder
	sb.WriteString("\n=== Soulcaster Anti-PatchSlop & Variant-Hunting Gate ===\n")
	if passed {
		sb.WriteString("Result:               PASSED (0 bypasses detected, compiler defenses intact)\n")
	} else {
		sb.WriteString("Result:               FAILED (Bypasses, PatchSlop, or ablated defenses detected)\n")
	}
	sb.WriteString(fmt.Sprintf("PatchSlop Detected:   %t\n", vRes.HasPatchSlop))
	sb.WriteString(fmt.Sprintf("Sanitizers Checked:   %d\n", len(vRes.Sanitizers)))
	sb.WriteString(fmt.Sprintf("Mutations Evaluated:  %d\n", vRes.TotalVariants))
	sb.WriteString(fmt.Sprintf("CFG Branch Bypasses:  %d\n", len(vRes.AdjacentBypasses)))

	if hRes != nil {
		sb.WriteString(fmt.Sprintf("Binary Evaluated:     %s\n", hRes.BinaryPath))
		sb.WriteString(fmt.Sprintf("  Non-Exec Stack:     %t\n", hRes.StackNonExecutable))
		sb.WriteString(fmt.Sprintf("  Stack Canary:       %t\n", hRes.StackCanaryPresent))
		sb.WriteString(fmt.Sprintf("  RELRO Level:        %s\n", hRes.RELRO))
		sb.WriteString(fmt.Sprintf("  Compiler Defenses:  %t\n", hRes.DefensesIntact))
	}

	if len(vRes.Violations) > 0 {
		sb.WriteString("\n[VIOLATIONS DETECTED]\n")
		for i, v := range vRes.Violations {
			sb.WriteString(fmt.Sprintf("  %d. [%s] (%s) %s\n", i+1, v.RuleID, v.Severity, v.Message))
			if v.HeadSnippet != "" {
				sb.WriteString(fmt.Sprintf("     Snippet: %s\n", v.HeadSnippet))
			}
		}
	}

	return sb.String()
}
