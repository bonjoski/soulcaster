package astdiff

import (
	"strings"
	"testing"
)

func TestGoRemovedAuthCheckDetection(t *testing.T) {
	baseCode := `package api

import (
	"context"
	"errors"
)

func HandleTransfer(ctx context.Context, user string, amount int) error {
	if !isAuthorized(user, "admin") {
		return errors.New("forbidden")
	}
	return executeTransfer(user, amount)
}
`

	// Head removes the isAuthorized check to make tests pass
	headCode := `package api

import (
	"context"
)

func HandleTransfer(ctx context.Context, user string, amount int) error {
	// Bypassed: direct execution
	return executeTransfer(user, amount)
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("api/transfer.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned unexpected error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to FAIL due to removed auth check, but it passed")
	}

	if res.Summary.AuthBypassViolations != 1 {
		t.Errorf("Expected 1 AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}

	if len(res.Violations) == 0 {
		t.Fatalf("Expected violations list to be populated")
	}

	v := res.Violations[0]
	if v.RuleID != RuleRemovedAuthCheck {
		t.Errorf("Expected RuleID %s, got %s", RuleRemovedAuthCheck, v.RuleID)
	}
	if v.Severity != SeverityCritical {
		t.Errorf("Expected severity %s, got %s", SeverityCritical, v.Severity)
	}
	if v.Function != "HandleTransfer" {
		t.Errorf("Expected Function 'HandleTransfer', got %s", v.Function)
	}
}

func TestGoAuthPreservedNoFalsePositive(t *testing.T) {
	baseCode := `package api

func ProcessPayment(user string) error {
	if err := checkPermission(user, "pay"); err != nil {
		return err
	}
	return nil
}
`

	headCode := `package api

func ProcessPayment(user string) error {
	// Updated or preserved permission check
	if err := checkPermission(user, "pay"); err != nil {
		return err
	}
	logSuccess(user)
	return nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("api/payment.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if !res.Passed {
		t.Errorf("Expected clean diff to pass, but violations found: %+v", res.Violations)
	}
	if res.Summary.TotalViolations != 0 {
		t.Errorf("Expected 0 violations, got %d", res.Summary.TotalViolations)
	}
}

func TestGoErrorSwallowedBlankAssignment(t *testing.T) {
	baseCode := `package worker

func RunTask() error {
	err := doOperation()
	if err != nil {
		return err
	}
	return nil
}
`

	// AI Agent patch silences error with _ = err
	headCode := `package worker

func RunTask() error {
	err := doOperation()
	_ = err
	return nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("worker/task.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to FAIL due to _ = err error swallowing, but it passed")
	}

	if res.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 ErrorSwallowingViolation, got %d", res.Summary.ErrorSwallowingViolations)
	}

	v := res.Violations[0]
	if v.RuleID != RuleErrorSwallowed {
		t.Errorf("Expected RuleID %s, got %s", RuleErrorSwallowed, v.RuleID)
	}
	if !strings.Contains(v.HeadSnippet, "_ = err") {
		t.Errorf("Expected HeadSnippet to contain '_ = err', got: %s", v.HeadSnippet)
	}
}

func TestGoErrorSwallowedEmptyIfBlock(t *testing.T) {
	baseCode := `package worker

func Process() {
	doInit()
}
`

	headCode := `package worker

func Process() {
	doInit()
	if err != nil {
		// silently ignored
	}
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("worker/process.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to FAIL due to empty if err != nil {}, but it passed")
	}

	if res.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 ErrorSwallowingViolation, got %d", res.Summary.ErrorSwallowingViolations)
	}
}

func TestGoDangerousMemoryUnsafePointer(t *testing.T) {
	baseCode := `package engine

func ProcessData(buf []byte) int {
	return len(buf)
}
`

	headCode := `package engine

import "unsafe"

func ProcessData(buf []byte) int {
	ptr := unsafe.Pointer(&buf[0])
	_ = ptr
	return len(buf)
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("engine/data.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to FAIL due to unsafe.Pointer, but it passed")
	}

	if res.Summary.DangerousMemoryViolations < 1 {
		t.Errorf("Expected at least 1 DangerousMemoryViolation, got %d", res.Summary.DangerousMemoryViolations)
	}
}

func TestGoDangerousMemoryUintptrArithmetic(t *testing.T) {
	baseCode := `package mem

func Offset(p uintptr) uintptr {
	return p
}
`

	headCode := `package mem

func Offset(p uintptr) uintptr {
	return p + uintptr(16)
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("mem/offset.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to FAIL due to uintptr arithmetic, but it passed")
	}

	if res.Summary.DangerousMemoryViolations != 1 {
		t.Errorf("Expected 1 DangerousMemoryViolation, got %d", res.Summary.DangerousMemoryViolations)
	}
}

func TestCleanDiffPassesWithoutFalsePositives(t *testing.T) {
	baseCode := `package utils

import "io"

func ReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
`

	headCode := `package utils

import (
	"fmt"
	"io"
)

func ReadAll(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return data, nil
}

func ByteCount(r io.Reader) (int, error) {
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	// n is an integer count, ignoring it with _ = n is legitimate
	_ = n
	return 1024, nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("utils/reader.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if !res.Passed {
		t.Errorf("Expected clean diff to pass, but got violations: %+v", res.Violations)
	}
}

func TestPythonDifferentialAnalysis(t *testing.T) {
	basePy := `
@jwt_required
def delete_account(user_id):
    db.delete_user(user_id)
`

	headPy := `
# AI agent removed @jwt_required to bypass test setup
def delete_account(user_id):
    try:
        db.delete_user(user_id)
    except Exception:
        pass
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("services/auth.py", []byte(basePy), []byte(headPy))
	if err != nil {
		t.Fatalf("Python analysis error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected Python analysis to fail")
	}

	if res.Summary.AuthBypassViolations != 1 {
		t.Errorf("Expected 1 Python AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}

	if res.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 Python ErrorSwallowingViolation, got %d", res.Summary.ErrorSwallowingViolations)
	}
}

func TestRustDifferentialAnalysis(t *testing.T) {
	baseRs := `
#[authorize(role = "admin")]
pub fn execute_mutation() -> Result<(), Error> {
    do_work()
}
`

	headRs := `
pub fn execute_mutation() -> Result<(), Error> {
    unsafe {
        raw_pointer_mutation();
    }
    Ok(())
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("src/mutation.rs", []byte(baseRs), []byte(headRs))
	if err != nil {
		t.Fatalf("Rust analysis error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected Rust analysis to fail")
	}

	if res.Summary.AuthBypassViolations != 1 {
		t.Errorf("Expected 1 Rust AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}

	if res.Summary.DangerousMemoryViolations != 1 {
		t.Errorf("Expected 1 Rust DangerousMemoryViolation, got %d", res.Summary.DangerousMemoryViolations)
	}
}
