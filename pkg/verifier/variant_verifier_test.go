package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/soulcaster/pkg/astdiff"
	"github.com/bonjoski/soulcaster/pkg/intoto"
)

func TestVerifyVariantPassesAndEmitsAttestation(t *testing.T) {
	tmpDir := t.TempDir()
	diffFile := filepath.Join(tmpDir, "clean.diff")
	binaryFile := filepath.Join(tmpDir, "binary.elf")
	attestFile := filepath.Join(tmpDir, "clean.diff.variant.intoto.jsonl")

	cleanDiff := `diff --git a/pkg/query/sanitize.go b/pkg/query/sanitize.go
index 1111111..2222222 100644
--- a/pkg/query/sanitize.go
+++ b/pkg/query/sanitize.go
@@ -10,6 +10,8 @@ func SanitizeInput(input string) string {
 	// Handles both quotes completely
+	input = strings.ReplaceAll(input, "\"", "")
+	input = strings.ReplaceAll(input, "'", "")
 	return input
 }
`
	if err := os.WriteFile(diffFile, []byte(cleanDiff), 0644); err != nil {
		t.Fatalf("Failed to write diff file: %v", err)
	}

	// Create valid ELF binary with all defenses
	elfData := buildSyntheticELF(false, true, true, false)
	if err := os.WriteFile(binaryFile, elfData, 0755); err != nil {
		t.Fatalf("Failed to write elf binary: %v", err)
	}

	opts := VariantVerificationOptions{
		DiffPath:        diffFile,
		TargetBinary:    binaryFile,
		AttestationPath: attestFile,
	}

	res, err := VerifyVariant(opts)
	if err != nil {
		t.Fatalf("VerifyVariant failed unexpectedly: %v", err)
	}

	if !res.Passed {
		t.Fatalf("Expected VerifyVariant to pass, but it failed: %s", res.Summary)
	}

	if res.Attestation == nil {
		t.Fatalf("Expected Attestation to be generated")
	}

	if res.Attestation.Predicate.GateResult != intoto.GateResultPassed {
		t.Errorf("Expected GateResult %s, got %s", intoto.GateResultPassed, res.Attestation.Predicate.GateResult)
	}

	// Verify attestation was written to disk
	attestBytes, err := os.ReadFile(attestFile)
	if err != nil {
		t.Fatalf("Failed to read emitted attestation file: %v", err)
	}

	parsedStmt, err := intoto.ParseVariantGateStatement(attestBytes)
	if err != nil {
		t.Fatalf("Failed to parse emitted attestation: %v", err)
	}

	if parsedStmt.PredicateType != intoto.VariantGatePredicateTypeV1 {
		t.Errorf("Expected predicate type %s, got %s", intoto.VariantGatePredicateTypeV1, parsedStmt.PredicateType)
	}
}

func TestVerifyVariantFailsOnPatchSlop(t *testing.T) {
	tmpDir := t.TempDir()
	diffFile := filepath.Join(tmpDir, "patchslop.diff")
	attestFile := filepath.Join(tmpDir, "patchslop.intoto.jsonl")

	// Pre-create stale attestation to verify it gets shredded
	_ = os.WriteFile(attestFile, []byte("stale-attestation"), 0644)

	patchSlopDiff := `diff --git a/pkg/query/sanitize.go b/pkg/query/sanitize.go
index 1111111..2222222 100644
--- a/pkg/query/sanitize.go
+++ b/pkg/query/sanitize.go
@@ -10,6 +10,7 @@ func SanitizeInput(input string) string {
 	// Incomplete quote stripping
+	input = strings.ReplaceAll(input, "\"", "")
 	return input
 }
`
	if err := os.WriteFile(diffFile, []byte(patchSlopDiff), 0644); err != nil {
		t.Fatalf("Failed to write diff file: %v", err)
	}

	opts := VariantVerificationOptions{
		DiffPath:        diffFile,
		AttestationPath: attestFile,
	}

	res, err := VerifyVariant(opts)
	if err != nil {
		t.Fatalf("VerifyVariant returned unexpected fatal error: %v", err)
	}

	if res.Passed {
		t.Errorf("Expected verification to FAIL on PatchSlop, but it passed")
	}

	if !res.VariantResult.HasPatchSlop {
		t.Errorf("Expected HasPatchSlop == true")
	}

	// Verify stale attestation was removed
	if _, statErr := os.Stat(attestFile); !os.IsNotExist(statErr) {
		t.Errorf("Expected stale attestation to be removed on failure")
	}
}

func TestVerifyVariantFailsOnStrippedCanaryBinary(t *testing.T) {
	tmpDir := t.TempDir()
	diffFile := filepath.Join(tmpDir, "clean.diff")
	binaryFile := filepath.Join(tmpDir, "vulnerable.elf")

	cleanDiff := `diff --git a/pkg/query/sanitize.go b/pkg/query/sanitize.go
index 1111111..2222222 100644
--- a/pkg/query/sanitize.go
+++ b/pkg/query/sanitize.go
@@ -10,6 +10,8 @@ func SanitizeInput(input string) string {
+	input = strings.ReplaceAll(input, "\"", "")
+	input = strings.ReplaceAll(input, "'", "")
 	return input
 }
`
	if err := os.WriteFile(diffFile, []byte(cleanDiff), 0644); err != nil {
		t.Fatalf("Failed to write diff: %v", err)
	}

	// Create binary with stripped stack canary
	elfData := buildSyntheticELF(false, false, true, false)
	if err := os.WriteFile(binaryFile, elfData, 0755); err != nil {
		t.Fatalf("Failed to write binary: %v", err)
	}

	opts := VariantVerificationOptions{
		DiffPath:     diffFile,
		TargetBinary: binaryFile,
	}

	res, err := VerifyVariant(opts)
	if err != nil {
		t.Fatalf("VerifyVariant returned unexpected fatal error: %v", err)
	}

	if res.Passed {
		t.Errorf("Expected verification to fail due to stripped canary in binary")
	}

	if res.HardeningResult == nil || res.HardeningResult.DefensesIntact {
		t.Errorf("Expected HardeningResult.DefensesIntact == false")
	}
}

func TestVerifyVariantWithFailingTestCmd(t *testing.T) {
	tmpDir := t.TempDir()
	diffFile := filepath.Join(tmpDir, "clean.diff")

	cleanDiff := `diff --git a/pkg/query/sanitize.go b/pkg/query/sanitize.go
index 1111111..2222222 100644
--- a/pkg/query/sanitize.go
+++ b/pkg/query/sanitize.go
@@ -10,6 +10,8 @@ func SanitizeInput(input string) string {
+	input = strings.ReplaceAll(input, "\"", "")
+	input = strings.ReplaceAll(input, "'", "")
 	return input
 }
`
	if err := os.WriteFile(diffFile, []byte(cleanDiff), 0644); err != nil {
		t.Fatalf("Failed to write diff: %v", err)
	}

	// Test command that rejects any payload containing %2522
	opts := VariantVerificationOptions{
		DiffPath: diffFile,
		TestCmd:  `if [ "$SOULCASTER_VARIANT_PAYLOAD" = "%2522" ]; then exit 1; else exit 0; fi`,
	}

	res, err := VerifyVariant(opts)
	if err != nil {
		t.Fatalf("VerifyVariant returned error: %v", err)
	}

	if res.Passed {
		t.Errorf("Expected verification to fail due to failing test command on %%2522 payload")
	}

	if res.VariantResult.BypassesDetected == 0 {
		t.Errorf("Expected BypassesDetected > 0")
	}

	foundViolation := false
	for _, v := range res.VariantResult.Violations {
		if v.RuleID == astdiff.RuleEncodingBypass && strings.Contains(v.Message, "%2522") {
			foundViolation = true
			break
		}
	}
	if !foundViolation {
		t.Errorf("Expected RuleEncodingBypass violation for %%2522")
	}
}
