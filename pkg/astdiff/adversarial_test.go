package astdiff

import (
	"strings"
	"testing"
)

// Probing adversarial evasion: AI Agent attempts to fool auth check by dead-coding it with 'if false && isAuthorized(...)'
func TestAdversarialRemovedAuthShortCircuitBypass(t *testing.T) {
	baseCode := `package server

func ExecuteAction(user string) error {
	if !isAuthorized(user, "admin") {
		return ErrForbidden
	}
	return runAction()
}
`

	headCode := `package server

func ExecuteAction(user string) error {
	// Adversarial evasion: keeping isAuthorized text in AST, but short-circuiting with constant false
	if false && isAuthorized(user, "admin") {
		return ErrForbidden
	}
	return runAction()
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("server/action.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Adversarial evasion succeeded: short-circuited auth check was NOT detected")
	}

	if res.Summary.AuthBypassViolations < 1 {
		t.Errorf("Expected at least 1 AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}
}

// Probing adversarial evasion: Dropping auth check on a pointer receiver method
func TestAdversarialRemovedAuthMethodReceiver(t *testing.T) {
	baseCode := `package service

type BankService struct {
	auth AuthClient
}

func (s *BankService) WireTransfer(ctx context.Context, from, to string, amount int64) error {
	if err := s.auth.VerifyToken(ctx); err != nil {
		return err
	}
	return s.executeWire(from, to, amount)
}
`

	headCode := `package service

type BankService struct {
	auth AuthClient
}

func (s *BankService) WireTransfer(ctx context.Context, from, to string, amount int64) error {
	// Agent removed s.auth.VerifyToken(ctx) check to pass mock unit test
	return s.executeWire(from, to, amount)
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("service/bank.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to fail when auth check is stripped from method receiver")
	}

	if res.Summary.AuthBypassViolations != 1 {
		t.Errorf("Expected 1 AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}

	if res.Violations[0].Function != "*BankService.WireTransfer" && res.Violations[0].Function != "(*BankService).WireTransfer" {
		t.Errorf("Expected Function '*BankService.WireTransfer', got %s", res.Violations[0].Function)
	}
}

// Probing adversarial evasion: Agent comments out auth check
func TestAdversarialRemovedAuthCommentOut(t *testing.T) {
	baseCode := `package router

func HandleAdmin(ctx context.Context) error {
	if err := checkPermission(ctx, "admin"); err != nil {
		return err
	}
	return wipeDatabase()
}
`

	headCode := `package router

func HandleAdmin(ctx context.Context) error {
	// checkPermission(ctx, "admin") - commented out for test suite
	return wipeDatabase()
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("router/admin.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Commented-out auth check was not detected by AST analysis")
	}
	if res.Summary.AuthBypassViolations != 1 {
		t.Errorf("Expected 1 AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}
}

// Probing adversarial evasion: Agent removes auth middleware registration from router chain
func TestAdversarialDroppedAuthMiddleware(t *testing.T) {
	baseCode := `package server

func SetupRoutes(r *Router) {
	r.Use(AuthMiddleware)
	r.HandleFunc("/api/data", HandleData)
}
`

	headCode := `package server

func SetupRoutes(r *Router) {
	// AuthMiddleware removed; only logging remains
	r.Use(LoggingMiddleware)
	r.HandleFunc("/api/data", HandleData)
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("server/routes.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected dropped AuthMiddleware to be flagged as violation")
	}
	if res.Summary.AuthBypassViolations != 1 {
		t.Errorf("Expected 1 AuthBypassViolation, got %d", res.Summary.AuthBypassViolations)
	}
}

// Probing adversarial evasion: Agent silences error via multi-assignment blanking
func TestAdversarialErrorSwallowMultiAssign(t *testing.T) {
	baseCode := `package fetcher

func FetchRecord(id string) ([]byte, error) {
	data, err := doFetch(id)
	if err != nil {
		return nil, err
	}
	return data, nil
}
`

	headCode := `package fetcher

func FetchRecord(id string) ([]byte, error) {
	data, err := doFetch(id)
	_ = err // silences error to prevent caller failure
	return data, nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("fetcher/fetch.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Multi-assign _ = err was not detected")
	}
	if res.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 ErrorSwallowingViolation, got %d", res.Summary.ErrorSwallowingViolations)
	}
}

// Probing adversarial evasion: Agent silences error inside a loop
func TestAdversarialErrorSwallowInLoop(t *testing.T) {
	baseCode := `package batch

func ProcessBatch(items []string) error {
	for _, item := range items {
		if err := process(item); err != nil {
			return err
		}
	}
	return nil
}
`

	headCode := `package batch

func ProcessBatch(items []string) error {
	for _, item := range items {
		err := process(item)
		_ = err
	}
	return nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("batch/batch.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Loop error swallowing was not detected")
	}
	if res.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 ErrorSwallowingViolation, got %d", res.Summary.ErrorSwallowingViolations)
	}
}

// Probing adversarial evasion: Agent introduces deferred bare recover closure
func TestAdversarialErrorSwallowBareRecover(t *testing.T) {
	baseCode := `package safe

func DoWork() {
	runRoutine()
}
`

	headCode := `package safe

func DoWork() {
	defer func() {
		recover() // silences panics without logging or handling
	}()
	runRoutine()
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("safe/work.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Bare recover closure was not detected")
	}
	if res.Summary.ErrorSwallowingViolations != 1 {
		t.Errorf("Expected 1 ErrorSwallowingViolation, got %d", res.Summary.ErrorSwallowingViolations)
	}
}

// Probing adversarial evasion: Agent aliases unsafe import (import u "unsafe")
func TestAdversarialDangerousMemoryAliasedUnsafe(t *testing.T) {
	baseCode := `package crypto

func Decrypt(b []byte) []byte {
	return b
}
`

	headCode := `package crypto

import u "unsafe"

func Decrypt(b []byte) []byte {
	ptr := u.Pointer(&b[0])
	_ = ptr
	return b
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("crypto/decrypt.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Aliased unsafe import (u.Pointer) was not detected")
	}
	if res.Summary.DangerousMemoryViolations < 1 {
		t.Errorf("Expected at least 1 DangerousMemoryViolation, got %d", res.Summary.DangerousMemoryViolations)
	}
}

// Probing adversarial evasion: Agent manipulates reflect.SliceHeader
func TestAdversarialDangerousMemoryReflectSliceHeader(t *testing.T) {
	baseCode := `package bytesutil

func CastSlice(s string) []byte {
	return []byte(s)
}
`

	headCode := `package bytesutil

import "reflect"

func CastSlice(s string) []byte {
	hdr := reflect.SliceHeader{
		Data: 0,
		Len: len(s),
		Cap: len(s),
	}
	_ = hdr
	return nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("bytesutil/cast.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("reflect.SliceHeader manipulation was not detected")
	}
	if res.Summary.DangerousMemoryViolations != 1 {
		t.Errorf("Expected 1 DangerousMemoryViolation, got %d", res.Summary.DangerousMemoryViolations)
	}
}

// Probing clean diff with complex valid error handling, ensuring ZERO false positives
func TestAdversarialCleanDiffWithComplexValidErrorHandling(t *testing.T) {
	baseCode := `package pipeline

type Task struct {
	ID string
}

func Process(t *Task) error {
	return nil
}
`

	headCode := `package pipeline

import (
	"context"
	"fmt"
	"log"
)

type Task struct {
	ID string
}

func Process(t *Task) error {
	ctx := context.Background()
	if err := validateTask(ctx, t); err != nil {
		log.Printf("validation failed: %v", err)
		return fmt.Errorf("task invalid: %w", err)
	}

	n, err := executeSubTask(t.ID)
	if err != nil {
		return fmt.Errorf("subtask failed: %w", err)
	}
	// Legitimate ignoring of count n, error was checked above
	_ = n

	return nil
}

func validateTask(ctx context.Context, t *Task) error {
	if t == nil {
		return fmt.Errorf("nil task")
	}
	return nil
}

func executeSubTask(id string) (int, error) {
	return len(id), nil
}
`

	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("pipeline/process.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if !res.Passed {
		t.Fatalf("Expected complex valid error handling to PASS without false positives, but got violations: %+v", res.Violations)
	}

	if res.Summary.TotalViolations != 0 {
		t.Errorf("Expected 0 violations, got %d", res.Summary.TotalViolations)
	}
}

// Probing machine-readable JSON diagnostic output on failure
func TestDiagnosticProofSerialization(t *testing.T) {
	baseCode := `package auth
func Login() {
	checkPermission()
}
`
	headCode := `package auth
func Login() {
	_ = err
}
`
	analyzer := NewAnalyzer()
	res, err := analyzer.AnalyzeSources("auth/login.go", []byte(baseCode), []byte(headCode))
	if err != nil {
		t.Fatalf("AnalyzeSources returned error: %v", err)
	}

	if res.Passed {
		t.Fatalf("Expected analysis to fail")
	}

	jsonBytes, err := res.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize diagnostic proof: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, "SEC-AST-001") {
		t.Errorf("Expected JSON to contain rule SEC-AST-001")
	}
	if !strings.Contains(jsonStr, "SEC-AST-002") {
		t.Errorf("Expected JSON to contain rule SEC-AST-002")
	}
	if !strings.Contains(jsonStr, `"passed": false`) {
		t.Errorf("Expected JSON to contain passed: false")
	}
}
