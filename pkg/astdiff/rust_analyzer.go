package astdiff

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// RustAnalyzer handles differential security analysis for Rust code.
type RustAnalyzer struct{}

func NewRustAnalyzer() *RustAnalyzer {
	return &RustAnalyzer{}
}

func (ra *RustAnalyzer) Language() string {
	return "rust"
}

func (ra *RustAnalyzer) CanAnalyze(filename string) bool {
	return filepath.Ext(filename) == ".rs"
}

var (
	rustAuthAttributeRegex = regexp.MustCompile(`#\[(?:authorize|permission|require_auth|has_role)[^\]]*\]`)
	rustUnsafeBlockRegex   = regexp.MustCompile(`\bunsafe\s*\{`)
	rustSwallowedErrRegex  = regexp.MustCompile(`let\s+_\s*=\s*.*(?:\?|\.unwrap_or_default\(\)|\.ok\(\))`)
)

func (ra *RustAnalyzer) AnalyzeSources(filename string, baseSource, headSource []byte, fileDiff *FileDiff) ([]Violation, error) {
	var violations []Violation

	baseAuth := extractRustAuth(baseSource)
	headAuth := extractRustAuth(headSource)

	// Rule 1: Removed Auth attribute
	for fnName, baseChecks := range baseAuth {
		headChecks, exists := headAuth[fnName]
		if !exists || len(headChecks) == 0 {
			for _, bc := range baseChecks {
				violations = append(violations, Violation{
					RuleID:      RuleRemovedAuthCheck,
					RuleName:    "RemovedAuthAttribute",
					Severity:    SeverityCritical,
					File:        filename,
					Line:        bc.Line,
					Function:    fnName,
					Message:     fmt.Sprintf("Authorization attribute %q present in base was removed from Rust function %s", bc.Snippet, fnName),
					BaseSnippet: bc.Snippet,
					ASTNodeType: "Attribute",
				})
			}
		}
	}

	// Rule 2: Swallowed error (let _ = ... unwrapped/silenced)
	headSwallows := extractRustSwallows(headSource)
	baseSwallows := extractRustSwallows(baseSource)
	for _, hs := range headSwallows {
		if !containsRustSnippet(baseSwallows, hs.Snippet) {
			violations = append(violations, Violation{
				RuleID:      RuleErrorSwallowed,
				RuleName:    "ErrorSwallowed",
				Severity:    SeverityHigh,
				File:        filename,
				Line:        hs.Line,
				Message:     fmt.Sprintf("Swallowed error in Rust assignment: %s", hs.Snippet),
				HeadSnippet: hs.Snippet,
				ASTNodeType: "LetStmt",
			})
		}
	}

	// Rule 3: Dangerous memory (unsafe block introduced)
	headUnsafe := extractRustUnsafe(headSource)
	baseUnsafe := extractRustUnsafe(baseSource)
	for _, hu := range headUnsafe {
		if !containsRustSnippet(baseUnsafe, hu.Snippet) {
			violations = append(violations, Violation{
				RuleID:      RuleDangerousMemory,
				RuleName:    "DangerousMemoryConstruct",
				Severity:    SeverityHigh,
				File:        filename,
				Line:        hu.Line,
				Message:     fmt.Sprintf("Unsafe memory block introduced in Rust: %s", hu.Snippet),
				HeadSnippet: hu.Snippet,
				ASTNodeType: "UnsafeBlock",
			})
		}
	}

	return violations, nil
}

type rustItem struct {
	Snippet string
	Line    int
}

func extractRustAuth(src []byte) map[string][]rustItem {
	result := make(map[string][]rustItem)
	if len(src) == 0 {
		return result
	}

	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0
	var pendingAttrs []rustItem

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if rustAuthAttributeRegex.MatchString(trimmed) {
			pendingAttrs = append(pendingAttrs, rustItem{
				Snippet: trimmed,
				Line:    lineNum,
			})
			continue
		}

		if strings.HasPrefix(trimmed, "pub fn ") || strings.HasPrefix(trimmed, "fn ") || strings.HasPrefix(trimmed, "async fn ") {
			fnParts := strings.Fields(trimmed)
			fnName := "unknown"
			for i, p := range fnParts {
				if p == "fn" && i+1 < len(fnParts) {
					fnName = fnParts[i+1]
					if idx := strings.Index(fnName, "("); idx != -1 {
						fnName = fnName[:idx]
					}
					if idx := strings.Index(fnName, "<"); idx != -1 {
						fnName = fnName[:idx]
					}
					break
				}
			}
			if len(pendingAttrs) > 0 {
				result[fnName] = append(result[fnName], pendingAttrs...)
				pendingAttrs = nil
			}
		} else if !strings.HasPrefix(trimmed, "#") {
			pendingAttrs = nil
		}
	}
	return result
}

func extractRustSwallows(src []byte) []rustItem {
	var items []rustItem
	if len(src) == 0 {
		return items
	}

	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if rustSwallowedErrRegex.MatchString(trimmed) {
			items = append(items, rustItem{
				Snippet: trimmed,
				Line:    lineNum,
			})
		}
	}
	return items
}

func extractRustUnsafe(src []byte) []rustItem {
	var items []rustItem
	if len(src) == 0 {
		return items
	}

	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if rustUnsafeBlockRegex.MatchString(trimmed) {
			items = append(items, rustItem{
				Snippet: trimmed,
				Line:    lineNum,
			})
		}
	}
	return items
}

func containsRustSnippet(list []rustItem, snippet string) bool {
	for _, it := range list {
		if strings.TrimSpace(it.Snippet) == strings.TrimSpace(snippet) {
			return true
		}
	}
	return false
}
