package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPatchFailureFailsClosed(t *testing.T) {
	tempDir := t.TempDir()

	baseFile := filepath.Join(tempDir, "base_transfer.go")
	headFile := filepath.Join(tempDir, "head_transfer.go")
	attestPath := filepath.Join(tempDir, "patch.gate.intoto.jsonl")

	baseCode := `package api

func Transfer(user string) error {
	if !isAuthorized(user) {
		return ErrForbidden
	}
	return nil
}
`
	// AI Agent drops auth check
	headCode := `package api

func Transfer(user string) error {
	return nil
}
`

	if err := os.WriteFile(baseFile, []byte(baseCode), 0644); err != nil {
		t.Fatalf("Failed to write base file: %v", err)
	}
	if err := os.WriteFile(headFile, []byte(headCode), 0644); err != nil {
		t.Fatalf("Failed to write head file: %v", err)
	}

	opts := PatchVerificationOptions{
		BaseFile:        baseFile,
		HeadFile:        headFile,
		AttestationPath: attestPath,
		WorkDir:         tempDir,
	}

	res, err := VerifyPatch(opts)
	if err != nil {
		t.Fatalf("VerifyPatch returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected VerifyPatch to FAIL closed, but it passed")
	}

	// Invariant: no attestation must exist on disk
	if _, err := os.Stat(attestPath); !os.IsNotExist(err) {
		t.Fatalf("Attestation file was emitted on failure! Expected fail-closed behavior.")
	}

	if res.DiagnosticJSON == "" {
		t.Fatalf("Expected non-empty DiagnosticJSON on failure")
	}

	if !strings.Contains(res.DiagnosticJSON, "SEC-AST-001") {
		t.Errorf("Expected DiagnosticJSON to contain SEC-AST-001, got: %s", res.DiagnosticJSON)
	}
}

func TestVerifyPatchSuccessEmitsAttestation(t *testing.T) {
	tempDir := t.TempDir()

	baseFile := filepath.Join(tempDir, "base_calc.go")
	headFile := filepath.Join(tempDir, "head_calc.go")
	attestPath := filepath.Join(tempDir, "calc.gate.intoto.jsonl")

	baseCode := `package calc

func Add(a, b int) int {
	return a + b
}
`

	headCode := `package calc

import "fmt"

func Add(a, b int) int {
	return a + b
}

func Divide(a, b int) (int, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	return a / b, nil
}
`

	if err := os.WriteFile(baseFile, []byte(baseCode), 0644); err != nil {
		t.Fatalf("Failed to write base file: %v", err)
	}
	if err := os.WriteFile(headFile, []byte(headCode), 0644); err != nil {
		t.Fatalf("Failed to write head file: %v", err)
	}

	opts := PatchVerificationOptions{
		BaseFile:        baseFile,
		HeadFile:        headFile,
		AttestationPath: attestPath,
		WorkDir:         tempDir,
		InvocationID:    "urn:uuid:test-patch-verify-1",
	}

	res, err := VerifyPatch(opts)
	if err != nil {
		t.Fatalf("VerifyPatch returned error: %v", err)
	}

	if !res.Passed {
		t.Fatalf("Expected clean patch to pass, but failed: %s", res.Summary)
	}

	// Verify attestation was written to disk
	if _, err := os.Stat(attestPath); err != nil {
		t.Fatalf("Attestation file not found on disk at %s: %v", attestPath, err)
	}

	// Verify the emitted attestation using VerifySecondaryGateAttestation
	stmt, err := VerifySecondaryGateAttestation(attestPath)
	if err != nil {
		t.Fatalf("VerifySecondaryGateAttestation failed: %v", err)
	}

	if stmt.Predicate.GateResult != "PASSED" {
		t.Errorf("Expected gateResult PASSED, got: %s", stmt.Predicate.GateResult)
	}

	if stmt.PredicateType != "https://bonjoski.github.io/attestation/secondary-vulnerability-gate/v1" {
		t.Errorf("Unexpected predicateType: %s", stmt.PredicateType)
	}
}

func TestVerifyPatchDirectoryComparison(t *testing.T) {
	tempDir := t.TempDir()

	baseDir := filepath.Join(tempDir, "base_repo")
	headDir := filepath.Join(tempDir, "head_repo")
	_ = os.MkdirAll(filepath.Join(baseDir, "pkg"), 0755)
	_ = os.MkdirAll(filepath.Join(headDir, "pkg"), 0755)

	baseFile := filepath.Join(baseDir, "pkg", "worker.go")
	headFile := filepath.Join(headDir, "pkg", "worker.go")

	baseCode := `package pkg

func Task() error {
	return nil
}
`

	// Head introduces _ = err error swallowing
	headCode := `package pkg

func Task() error {
	err := doWork()
	_ = err
	return nil
}

func doWork() error { return nil }
`

	_ = os.WriteFile(baseFile, []byte(baseCode), 0644)
	_ = os.WriteFile(headFile, []byte(headCode), 0644)

	opts := PatchVerificationOptions{
		BaseDir: baseDir,
		HeadDir: headDir,
		WorkDir: tempDir,
	}

	res, err := VerifyPatch(opts)
	if err != nil {
		t.Fatalf("VerifyPatch returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected directory comparison with introduced _ = err to FAIL, but passed")
	}

	if res.Analysis.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 ErrorSwallowingViolation, got %d", res.Analysis.Summary.ErrorSwallowingViolations)
	}
}
