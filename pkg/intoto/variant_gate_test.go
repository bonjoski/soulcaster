package intoto

import (
	"strings"
	"testing"
	"time"
)

func TestVariantGateStatementRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	subjects := []ResourceDescriptor{
		{
			Name: "patch.diff",
			Digest: DigestSet{
				"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
		},
	}

	summary := VariantGateSummary{
		TotalVariantsGenerated:   15,
		BypassesDetected:         0,
		EncodingVariants:         5,
		UnicodeVariants:          4,
		OverlongVariants:         3,
		NullByteVariants:         3,
		AdjacentBranchBypasses:   0,
		CompilerDefensesVerified: true,
		CompilerDefensesIntact:   true,
	}

	stmt := NewVariantGateStatement(
		subjects,
		"patch.diff",
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"",
		"",
		true,
		summary,
		nil,
		"0.1.0",
		"urn:uuid:test-invocation",
		&now,
		&now,
	)

	if err := stmt.Validate(); err != nil {
		t.Fatalf("Statement validation failed: %v", err)
	}

	jsonl, err := stmt.ToJSONL()
	if err != nil {
		t.Fatalf("ToJSONL failed: %v", err)
	}

	if !strings.HasSuffix(string(jsonl), "\n") {
		t.Errorf("Expected trailing newline in JSONL")
	}

	parsed, err := ParseVariantGateStatement(jsonl)
	if err != nil {
		t.Fatalf("ParseVariantGateStatement failed: %v", err)
	}

	if parsed.Predicate.GateResult != GateResultPassed {
		t.Errorf("Expected GateResult %s, got %s", GateResultPassed, parsed.Predicate.GateResult)
	}

	if parsed.Predicate.Summary.TotalVariantsGenerated != 15 {
		t.Errorf("Expected 15 variants, got %d", parsed.Predicate.Summary.TotalVariantsGenerated)
	}
}

func TestVariantGateStatementValidationErrors(t *testing.T) {
	stmt := &VariantGateStatement{
		Type:          "invalid-type",
		PredicateType: VariantGatePredicateTypeV1,
	}

	if err := stmt.Validate(); err == nil {
		t.Errorf("Expected validation failure for invalid type")
	}
}
