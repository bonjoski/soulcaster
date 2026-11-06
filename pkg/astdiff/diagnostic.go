package astdiff

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity represents the severity ranking of a secondary flaw.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// RuleID identifies a specific differential AST security rule.
type RuleID string

const (
	RuleRemovedAuthCheck RuleID = "SEC-AST-001"
	RuleErrorSwallowed   RuleID = "SEC-AST-002"
	RuleDangerousMemory  RuleID = "SEC-AST-003"
)

// Violation describes a concrete AST security flaw detected in a diff.
type Violation struct {
	RuleID      RuleID            `json:"ruleId"`
	RuleName    string            `json:"ruleName"`
	Severity    Severity          `json:"severity"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Function    string            `json:"function,omitempty"`
	Message     string            `json:"message"`
	BaseSnippet string            `json:"baseSnippet,omitempty"`
	HeadSnippet string            `json:"headSnippet,omitempty"`
	ASTNodeType string            `json:"astNodeType,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Summary provides aggregate metrics of the differential AST analysis.
type Summary struct {
	TotalFilesAnalyzed        int `json:"totalFilesAnalyzed"`
	TotalViolations           int `json:"totalViolations"`
	AuthBypassViolations      int `json:"authBypassViolations"`
	ErrorSwallowingViolations int `json:"errorSwallowingViolations"`
	DangerousMemoryViolations int `json:"dangerousMemoryViolations"`
}

// AnalysisResult holds the overall evaluation of a patch or diff.
type AnalysisResult struct {
	Passed      bool        `json:"passed"`
	Gate        string      `json:"gate"`
	EvaluatedAt time.Time   `json:"evaluatedAt"`
	BaseRef     string      `json:"baseRef,omitempty"`
	HeadRef     string      `json:"headRef,omitempty"`
	Files       []string    `json:"files"`
	Summary     Summary     `json:"summary"`
	Violations  []Violation `json:"violations"`
}

// NewAnalysisResult initializes an empty AnalysisResult.
func NewAnalysisResult(baseRef, headRef string) *AnalysisResult {
	return &AnalysisResult{
		Passed:      true,
		Gate:        "secondary-vulnerability-gate",
		EvaluatedAt: time.Now().UTC(),
		BaseRef:     baseRef,
		HeadRef:     headRef,
		Files:       make([]string, 0),
		Summary:     Summary{},
		Violations:  make([]Violation, 0),
	}
}

// AddViolation appends a violation and updates summary statistics.
func (r *AnalysisResult) AddViolation(v Violation) {
	r.Passed = false
	r.Violations = append(r.Violations, v)
	r.Summary.TotalViolations++

	switch v.RuleID {
	case RuleRemovedAuthCheck:
		r.Summary.AuthBypassViolations++
	case RuleErrorSwallowed:
		r.Summary.ErrorSwallowingViolations++
	case RuleDangerousMemory:
		r.Summary.DangerousMemoryViolations++
	}
}

// ToJSON serializes the result into machine-readable JSON bytes.
func (r *AnalysisResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// FormatDiagnosticReport generates a formatted human-readable terminal report.
func (r *AnalysisResult) FormatDiagnosticReport() string {
	var sb strings.Builder

	if r.Passed {
		sb.WriteString("[PASS] Soulcaster Secondary-Vulnerability CI Gate Passed\n")
		sb.WriteString(fmt.Sprintf("  Files Analyzed: %d\n", r.Summary.TotalFilesAnalyzed))
		sb.WriteString("  Violations: 0 detected (Zero CWE-bench v2 secondary flaw regressions)\n")
		return sb.String()
	}

	sb.WriteString("[FAIL] Soulcaster Secondary-Vulnerability CI Gate BLOCKED Patch\n")
	sb.WriteString(fmt.Sprintf("  Total Regressions: %d\n", r.Summary.TotalViolations))
	sb.WriteString(fmt.Sprintf("  Auth Bypass / Removed Checks: %d\n", r.Summary.AuthBypassViolations))
	sb.WriteString(fmt.Sprintf("  Error Swallowing Regressions: %d\n", r.Summary.ErrorSwallowingViolations))
	sb.WriteString(fmt.Sprintf("  Dangerous Memory Regressions: %d\n\n", r.Summary.DangerousMemoryViolations))
	sb.WriteString("Diagnostic Proof of Detected Regressions:\n")

	for i, v := range r.Violations {
		sb.WriteString(fmt.Sprintf("  [%d] %s (%s) - %s\n", i+1, v.RuleID, v.Severity, v.RuleName))
		sb.WriteString(fmt.Sprintf("      Location: %s:%d", v.File, v.Line))
		if v.Function != "" {
			sb.WriteString(fmt.Sprintf(" (in %s)", v.Function))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("      Finding:  %s\n", v.Message))
		if v.BaseSnippet != "" {
			sb.WriteString(fmt.Sprintf("      Base:     %s\n", strings.TrimSpace(v.BaseSnippet)))
		}
		if v.HeadSnippet != "" {
			sb.WriteString(fmt.Sprintf("      Head:     %s\n", strings.TrimSpace(v.HeadSnippet)))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
