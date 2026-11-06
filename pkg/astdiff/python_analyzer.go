package astdiff

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// PythonAnalyzer handles differential security analysis for Python code.
type PythonAnalyzer struct{}

func NewPythonAnalyzer() *PythonAnalyzer {
	return &PythonAnalyzer{}
}

func (pa *PythonAnalyzer) Language() string {
	return "python"
}

func (pa *PythonAnalyzer) CanAnalyze(filename string) bool {
	ext := filepath.Ext(filename)
	return ext == ".py" || ext == ".pyw"
}

var (
	pyAuthDecoratorRegex = regexp.MustCompile(`@([a-zA-Z0-9_.]*(?:auth|jwt|login|permission|role|require)[a-zA-Z0-9_.]*)`)
	pyAuthCallRegex      = regexp.MustCompile(`(?:check_permission|verify_token|is_authorized|has_role|require_auth|authenticate)\s*\(`)
	pyBareExceptRegex    = regexp.MustCompile(`except\s*(?:Exception)?\s*(?:as\s+[a-zA-Z0-9_]+)?\s*:`)
	pyPassRegex          = regexp.MustCompile(`^\s*pass\s*$`)
	pyCtypesMemoryRegex  = regexp.MustCompile(`ctypes\.(?:cast|POINTER|memmove|addressof|string_at|wstring_at)`)
)

func (pa *PythonAnalyzer) AnalyzeSources(filename string, baseSource, headSource []byte, fileDiff *FileDiff) ([]Violation, error) {
	var violations []Violation

	baseAuth := extractPythonAuth(baseSource)
	headAuth := extractPythonAuth(headSource)

	// Rule 1: Removed Auth
	for fnName, baseChecks := range baseAuth {
		headChecks, exists := headAuth[fnName]
		if !exists || len(headChecks) == 0 {
			for _, bc := range baseChecks {
				violations = append(violations, Violation{
					RuleID:      RuleRemovedAuthCheck,
					RuleName:    "RemovedAuthDecorator",
					Severity:    SeverityCritical,
					File:        filename,
					Line:        bc.Line,
					Function:    fnName,
					Message:     fmt.Sprintf("Authorization check/decorator %q present in base was removed in Python function %s", bc.Snippet, fnName),
					BaseSnippet: bc.Snippet,
					ASTNodeType: "Decorator",
				})
			}
		}
	}

	// Rule 2: Error swallowing (except: pass)
	headSwallows := extractPythonSwallows(headSource)
	baseSwallows := extractPythonSwallows(baseSource)
	for _, hs := range headSwallows {
		if !containsPythonSnippet(baseSwallows, hs.Snippet) {
			violations = append(violations, Violation{
				RuleID:      RuleErrorSwallowed,
				RuleName:    "ErrorSwallowed",
				Severity:    SeverityHigh,
				File:        filename,
				Line:        hs.Line,
				Message:     fmt.Sprintf("Swallowed exception block detected: %s", hs.Snippet),
				HeadSnippet: hs.Snippet,
				ASTNodeType: "TryExcept",
			})
		}
	}

	// Rule 3: Dangerous memory constructs (ctypes pointer manipulations)
	headMem := extractPythonMemory(headSource)
	baseMem := extractPythonMemory(baseSource)
	for _, hm := range headMem {
		if !containsPythonSnippet(baseMem, hm.Snippet) {
			violations = append(violations, Violation{
				RuleID:      RuleDangerousMemory,
				RuleName:    "DangerousMemoryConstruct",
				Severity:    SeverityHigh,
				File:        filename,
				Line:        hm.Line,
				Message:     fmt.Sprintf("Dangerous pointer or ctypes construct introduced: %s", hm.Snippet),
				HeadSnippet: hm.Snippet,
				ASTNodeType: "CtypesMemory",
			})
		}
	}

	return violations, nil
}

type pythonItem struct {
	Snippet string
	Line    int
}

func extractPythonAuth(src []byte) map[string][]pythonItem {
	result := make(map[string][]pythonItem)
	if len(src) == 0 {
		return result
	}

	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0
	var pendingDecorators []pythonItem

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if pyAuthDecoratorRegex.MatchString(trimmed) {
			pendingDecorators = append(pendingDecorators, pythonItem{
				Snippet: trimmed,
				Line:    lineNum,
			})
			continue
		}

		if strings.HasPrefix(trimmed, "def ") {
			fnName := strings.TrimPrefix(trimmed, "def ")
			if idx := strings.Index(fnName, "("); idx != -1 {
				fnName = strings.TrimSpace(fnName[:idx])
			}
			if len(pendingDecorators) > 0 {
				result[fnName] = append(result[fnName], pendingDecorators...)
				pendingDecorators = nil
			}
		} else if !strings.HasPrefix(trimmed, "@") {
			pendingDecorators = nil
		}
	}
	return result
}

func extractPythonSwallows(src []byte) []pythonItem {
	var items []pythonItem
	if len(src) == 0 {
		return items
	}

	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0
	var inExcept bool
	var exceptLine int
	var exceptSnippet string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if pyBareExceptRegex.MatchString(trimmed) {
			inExcept = true
			exceptLine = lineNum
			exceptSnippet = trimmed
			continue
		}

		if inExcept {
			if pyPassRegex.MatchString(trimmed) || trimmed == "..." {
				items = append(items, pythonItem{
					Snippet: fmt.Sprintf("%s\n    %s", exceptSnippet, trimmed),
					Line:    exceptLine,
				})
			}
			inExcept = false
		}
	}
	return items
}

func extractPythonMemory(src []byte) []pythonItem {
	var items []pythonItem
	if len(src) == 0 {
		return items
	}

	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if pyCtypesMemoryRegex.MatchString(trimmed) {
			items = append(items, pythonItem{
				Snippet: trimmed,
				Line:    lineNum,
			})
		}
	}
	return items
}

func containsPythonSnippet(list []pythonItem, snippet string) bool {
	for _, it := range list {
		if strings.TrimSpace(it.Snippet) == strings.TrimSpace(snippet) {
			return true
		}
	}
	return false
}
