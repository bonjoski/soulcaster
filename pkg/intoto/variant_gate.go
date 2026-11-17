package intoto

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// VariantGatePredicateTypeV1 is the URI for the variant-hunting gate predicate.
	VariantGatePredicateTypeV1 = "https://bonjoski.github.io/attestation/variant-gate/v1"
)

// VariantGateSummary summarizes the variant hunting results and compiler hardening checks.
type VariantGateSummary struct {
	TotalVariantsGenerated   int  `json:"totalVariantsGenerated"`
	BypassesDetected         int  `json:"bypassesDetected"`
	EncodingVariants         int  `json:"encodingVariants"`
	UnicodeVariants          int  `json:"unicodeVariants"`
	OverlongVariants         int  `json:"overlongVariants"`
	NullByteVariants         int  `json:"nullByteVariants"`
	AdjacentBranchBypasses   int  `json:"adjacentBranchBypasses"`
	CompilerDefensesVerified bool `json:"compilerDefensesVerified"`
	CompilerDefensesIntact   bool `json:"compilerDefensesIntact"`
}

// VariantDiagnosticProof represents machine-readable proof of an identified bypass or defense ablation.
type VariantDiagnosticProof struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
	Payload  string `json:"payload,omitempty"`
	Category string `json:"category,omitempty"`
}

// VariantGatePredicate defines the in-toto v1.0 predicate for the variant hunting gate.
type VariantGatePredicate struct {
	GateResult               string                   `json:"gateResult"`
	PolicyVersion            string                   `json:"policyVersion"`
	EvaluatedAt              time.Time                `json:"evaluatedAt"`
	PatchFile                string                   `json:"patchFile,omitempty"`
	PatchDigest              string                   `json:"patchDigest,omitempty"`
	TargetBinary             string                   `json:"targetBinary,omitempty"`
	TargetBinaryDigest       string                   `json:"targetBinaryDigest,omitempty"`
	Summary                  VariantGateSummary       `json:"summary"`
	Diagnostics              []VariantDiagnosticProof `json:"diagnostics,omitempty"`
	Builder                  Builder                  `json:"builder"`
	Metadata                 BuildMetadata            `json:"metadata"`
}

// VariantGateStatement represents an in-toto v1.0 Statement envelope for the variant gate.
type VariantGateStatement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     VariantGatePredicate `json:"predicate"`
}

// NewVariantGateStatement constructs an in-toto statement for the variant hunting gate.
func NewVariantGateStatement(
	subjects []ResourceDescriptor,
	patchFile, patchDigest string,
	targetBinary, targetBinaryDigest string,
	passed bool,
	summary VariantGateSummary,
	diagnostics []VariantDiagnosticProof,
	builderVersion string,
	invocationID string,
	startedOn, finishedOn *time.Time,
) *VariantGateStatement {
	gateResult := GateResultPassed
	if !passed {
		gateResult = GateResultFailed
	}

	evalTime := time.Now().UTC()
	if startedOn != nil {
		evalTime = *startedOn
	}

	return &VariantGateStatement{
		Type:          StatementTypeV1,
		Subject:       subjects,
		PredicateType: VariantGatePredicateTypeV1,
		Predicate: VariantGatePredicate{
			GateResult:         gateResult,
			PolicyVersion:      "v1.0.0",
			EvaluatedAt:        evalTime,
			PatchFile:          patchFile,
			PatchDigest:        patchDigest,
			TargetBinary:       targetBinary,
			TargetBinaryDigest: targetBinaryDigest,
			Summary:            summary,
			Diagnostics:        diagnostics,
			Builder: Builder{
				ID: SoulcasterBuilderID,
				Version: map[string]string{
					"soulcaster": builderVersion,
				},
			},
			Metadata: BuildMetadata{
				InvocationID: invocationID,
				StartedOn:    startedOn,
				FinishedOn:   finishedOn,
			},
		},
	}
}

// ToJSON returns pretty-printed JSON bytes.
func (s *VariantGateStatement) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// ToJSONL returns single-line JSON bytes terminated with newline.
func (s *VariantGateStatement) ToJSONL() ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseVariantGateStatement parses and validates a variant gate in-toto statement.
func ParseVariantGateStatement(data []byte) (*VariantGateStatement, error) {
	var stmt VariantGateStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal variant gate statement: %w", err)
	}
	if err := stmt.Validate(); err != nil {
		return nil, err
	}
	return &stmt, nil
}

// Validate validates that the statement conforms to in-toto v1.0 and variant gate predicate requirements.
func (s *VariantGateStatement) Validate() error {
	if s.Type != StatementTypeV1 {
		return fmt.Errorf("invalid _type: expected %q, got %q", StatementTypeV1, s.Type)
	}
	if s.PredicateType != VariantGatePredicateTypeV1 {
		return fmt.Errorf("invalid predicateType: expected %q, got %q", VariantGatePredicateTypeV1, s.PredicateType)
	}
	if len(s.Subject) == 0 {
		return fmt.Errorf("invalid statement: subject list cannot be empty")
	}
	for i, subj := range s.Subject {
		if subj.Name == "" {
			return fmt.Errorf("subject[%d] name is required", i)
		}
		if len(subj.Digest) == 0 {
			return fmt.Errorf("subject[%d] %q has empty digest set", i, subj.Name)
		}
		if _, ok := subj.Digest["sha256"]; !ok {
			return fmt.Errorf("subject[%d] %q is missing sha256 digest", i, subj.Name)
		}
	}
	if s.Predicate.GateResult != GateResultPassed && s.Predicate.GateResult != GateResultFailed {
		return fmt.Errorf("invalid gateResult: must be %q or %q, got %q", GateResultPassed, GateResultFailed, s.Predicate.GateResult)
	}
	return nil
}
