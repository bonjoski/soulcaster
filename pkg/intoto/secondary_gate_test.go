package intoto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSecondaryGateStatementSchema(t *testing.T) {
	now := time.Now().UTC()
	subject := []ResourceDescriptor{
		{
			Name: "agent-patch",
			Digest: DigestSet{
				"sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			},
		},
	}

	summary := GateChecksSummary{
		TotalFilesAnalyzed:        3,
		TotalViolations:           0,
		AuthBypassViolations:      0,
		ErrorSwallowingViolations: 0,
		DangerousMemoryViolations: 0,
	}

	stmt := NewSecondaryGateStatement(
		subject,
		"main",
		"feat/remediation",
		[]string{"api/transfer.go", "db/conn.go", "utils/crypto.go"},
		true,
		summary,
		nil,
		"0.1.0",
		"urn:uuid:test-gate-1234",
		&now,
		&now,
	)

	// 1. Validate statement struct
	if err := stmt.Validate(); err != nil {
		t.Fatalf("Secondary gate statement validation failed: %v", err)
	}

	// 2. Validate JSON output
	jsonBytes, err := stmt.ToJSON()
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if raw["_type"] != StatementTypeV1 {
		t.Errorf("Expected _type %s, got %v", StatementTypeV1, raw["_type"])
	}
	if raw["predicateType"] != SecondaryVulnerabilityGatePredicateTypeV1 {
		t.Errorf("Expected predicateType %s, got %v", SecondaryVulnerabilityGatePredicateTypeV1, raw["predicateType"])
	}

	// 3. Validate JSONL output
	jsonlBytes, err := stmt.ToJSONL()
	if err != nil {
		t.Fatalf("Failed to marshal JSONL: %v", err)
	}
	if !strings.HasSuffix(string(jsonlBytes), "\n") {
		t.Errorf("JSONL output must end with newline")
	}

	// 4. Test ParseSecondaryGateStatement
	parsed, err := ParseSecondaryGateStatement(jsonBytes)
	if err != nil {
		t.Fatalf("ParseSecondaryGateStatement failed: %v", err)
	}

	if parsed.Predicate.GateResult != GateResultPassed {
		t.Errorf("Expected GateResultPassed, got %s", parsed.Predicate.GateResult)
	}
	if len(parsed.Predicate.FilesEvaluated) != 3 {
		t.Errorf("Expected 3 files evaluated, got %d", len(parsed.Predicate.FilesEvaluated))
	}
}

func TestSecondaryGateStatementValidationErrors(t *testing.T) {
	// Missing subject
	stmt := &SecondaryGateStatement{
		Type:          StatementTypeV1,
		PredicateType: SecondaryVulnerabilityGatePredicateTypeV1,
		Predicate: SecondaryGatePredicate{
			GateResult: GateResultPassed,
		},
	}
	if err := stmt.Validate(); err == nil {
		t.Errorf("Expected validation error on empty subject")
	}

	// Wrong predicate type
	stmt.Subject = []ResourceDescriptor{
		{Name: "patch", Digest: DigestSet{"sha256": "1234"}},
	}
	stmt.PredicateType = "https://invalid.org"
	if err := stmt.Validate(); err == nil {
		t.Errorf("Expected validation error on wrong predicateType")
	}
}
