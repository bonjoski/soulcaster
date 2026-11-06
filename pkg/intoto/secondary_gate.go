package intoto

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// SecondaryVulnerabilityGatePredicateTypeV1 is the URI for the secondary vulnerability gate predicate.
	SecondaryVulnerabilityGatePredicateTypeV1 = "https://bonjoski.github.io/attestation/secondary-vulnerability-gate/v1"
	// GateResultPassed indicates the patch passed all secondary vulnerability checks.
	GateResultPassed = "PASSED"
	// GateResultFailed indicates the patch failed one or more secondary vulnerability checks.
	GateResultFailed = "FAILED"
)

// GateChecksSummary summarizes the checks performed and violations detected.
type GateChecksSummary struct {
	TotalFilesAnalyzed        int `json:"totalFilesAnalyzed"`
	TotalViolations           int `json:"totalViolations"`
	AuthBypassViolations      int `json:"authBypassViolations"`
	ErrorSwallowingViolations int `json:"errorSwallowingViolations"`
	DangerousMemoryViolations int `json:"dangerousMemoryViolations"`
}

// GateDiagnosticProof represents machine-readable proof of a detected flaw.
type GateDiagnosticProof struct {
	RuleID      string            `json:"ruleId"`
	RuleName    string            `json:"ruleName"`
	Severity    string            `json:"severity"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Function    string            `json:"function,omitempty"`
	Message     string            `json:"message"`
	BaseSnippet string            `json:"baseSnippet,omitempty"`
	HeadSnippet string            `json:"headSnippet,omitempty"`
	ASTNodeType string            `json:"astNodeType,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecondaryGatePredicate defines the SLSA / in-toto predicate for the secondary-vulnerability gate.
type SecondaryGatePredicate struct {
	GateResult     string                `json:"gateResult"`
	PolicyVersion  string                `json:"policyVersion"`
	EvaluatedAt    time.Time             `json:"evaluatedAt"`
	BaseRef        string                `json:"baseRef,omitempty"`
	HeadRef        string                `json:"headRef,omitempty"`
	FilesEvaluated []string              `json:"filesEvaluated"`
	ChecksSummary  GateChecksSummary     `json:"checksSummary"`
	Diagnostics    []GateDiagnosticProof `json:"diagnostics,omitempty"`
	Builder        Builder               `json:"builder"`
	Metadata       BuildMetadata         `json:"metadata"`
}

// SecondaryGateStatement represents an in-toto v1.0 Statement envelope for the secondary vulnerability gate.
type SecondaryGateStatement struct {
	Type          string                 `json:"_type"`
	Subject       []ResourceDescriptor   `json:"subject"`
	PredicateType string                 `json:"predicateType"`
	Predicate     SecondaryGatePredicate `json:"predicate"`
}

// NewSecondaryGateStatement creates a new in-toto statement for the secondary vulnerability gate.
func NewSecondaryGateStatement(
	subjects []ResourceDescriptor,
	baseRef, headRef string,
	filesEvaluated []string,
	passed bool,
	summary GateChecksSummary,
	diagnostics []GateDiagnosticProof,
	builderVersion string,
	invocationID string,
	startedOn, finishedOn *time.Time,
) *SecondaryGateStatement {
	gateResult := GateResultPassed
	if !passed {
		gateResult = GateResultFailed
	}

	evalTime := time.Now().UTC()
	if startedOn != nil {
		evalTime = *startedOn
	}

	return &SecondaryGateStatement{
		Type:          StatementTypeV1,
		Subject:       subjects,
		PredicateType: SecondaryVulnerabilityGatePredicateTypeV1,
		Predicate: SecondaryGatePredicate{
			GateResult:     gateResult,
			PolicyVersion:  "v1.0.0",
			EvaluatedAt:    evalTime,
			BaseRef:        baseRef,
			HeadRef:        headRef,
			FilesEvaluated: filesEvaluated,
			ChecksSummary:  summary,
			Diagnostics:    diagnostics,
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
func (s *SecondaryGateStatement) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// ToJSONL returns single-line JSON bytes terminated with newline.
func (s *SecondaryGateStatement) ToJSONL() ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseSecondaryGateStatement parses and validates a secondary gate in-toto statement.
func ParseSecondaryGateStatement(data []byte) (*SecondaryGateStatement, error) {
	var stmt SecondaryGateStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secondary gate statement: %w", err)
	}
	if err := stmt.Validate(); err != nil {
		return nil, err
	}
	return &stmt, nil
}

// Validate validates that the statement conforms to in-toto v1.0 and secondary gate predicate requirements.
func (s *SecondaryGateStatement) Validate() error {
	if s.Type != StatementTypeV1 {
		return fmt.Errorf("invalid _type: expected %q, got %q", StatementTypeV1, s.Type)
	}
	if s.PredicateType != SecondaryVulnerabilityGatePredicateTypeV1 {
		return fmt.Errorf("invalid predicateType: expected %q, got %q", SecondaryVulnerabilityGatePredicateTypeV1, s.PredicateType)
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
