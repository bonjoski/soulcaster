package astdiff

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
)

// MutationCategory identifies the adversarial mutation technique applied.
type MutationCategory string

const (
	MutationQuoteSubstitution MutationCategory = "QUOTE_SUBSTITUTION"
	MutationDoubleURLEncoding MutationCategory = "DOUBLE_URL_ENCODING"
	MutationUnicodeFullwidth  MutationCategory = "UNICODE_FULLWIDTH"
	MutationOverlongUTF8      MutationCategory = "OVERLONG_UTF8"
	MutationNullByteInjection MutationCategory = "NULL_BYTE_INJECTION"
	MutationAdjacentBranch    MutationCategory = "ADJACENT_BRANCH_BYPASS"
)

// VariantMutation represents a concrete adversarial test mutation payload.
type VariantMutation struct {
	Category    MutationCategory `json:"category"`
	Target      string           `json:"target"`
	Payload     string           `json:"payload"`
	Description string           `json:"description"`
}

// AdjacentBranchBypass represents an unhandled execution path in the CFG adjacent to the patch.
type AdjacentBranchBypass struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Function    string `json:"function,omitempty"`
	BranchName  string `json:"branchName"`
	Description string `json:"description"`
}

// DetectedSanitizer captures details of a newly introduced sanitization or branch check.
type DetectedSanitizer struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	Snippet       string `json:"snippet"`
	Kind          string `json:"kind"` // "string_replace", "regex", "branch_condition", "char_filter"
	TargetChar    string `json:"targetChar"`
	IsDoubleQuote bool   `json:"isDoubleQuote"`
	IsSingleQuote bool   `json:"isSingleQuote"`
	IsRegex       bool   `json:"isRegex"`
	IsBranch      bool   `json:"isBranch"`
}

// VariantHunterResult holds the complete outcome of variant analysis and mutation generation.
type VariantHunterResult struct {
	Passed           bool                   `json:"passed"`
	HasPatchSlop     bool                   `json:"hasPatchSlop"`
	Sanitizers       []DetectedSanitizer    `json:"sanitizers"`
	Mutations        []VariantMutation      `json:"mutations"`
	AdjacentBypasses []AdjacentBranchBypass `json:"adjacentBypasses"`
	Violations       []Violation            `json:"violations"`
	TotalVariants    int                    `json:"totalVariants"`
	BypassesDetected int                    `json:"bypassesDetected"`
	Summary          string                 `json:"summary"`
}

// Common patterns for detecting newly added sanitizers, replacements, regexes, and checks.
var (
	rxStringReplace = regexp.MustCompile(`(?i)(strings\.(?:Replace|ReplaceAll)|(?:\.replace|\.replaceAll)\s*\(|re\.sub\s*\()`)
	rxRegexCompile  = regexp.MustCompile(`(?i)(regexp\.(?:Compile|MustCompile)|re\.compile\s*\(|Regex::new\s*\()`)
	rxFilterCheck   = regexp.MustCompile(`(?i)(strings\.(?:Contains|Index|Trim|HasPrefix|HasSuffix)|(?:\.includes|\.indexOf|\.contains)\s*\(|sanitize|escape|filter)`)
	rxBranchCond    = regexp.MustCompile(`(?i)^\s*(if\s+|else\s+if\s+|elif\s+|case\s+|when\s+)`)
)

// AnalyzePatchVariants parses a unified diff, detects patch sanitizers/checks,
// identifies PatchSlop (such as incomplete quote stripping), searches for CFG adjacent branch bypasses,
// and generates adversarial variant mutations.
func AnalyzePatchVariants(diffData []byte) (*VariantHunterResult, error) {
	fileDiffs, err := ParsePatch(diffData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse patch diff: %w", err)
	}

	result := &VariantHunterResult{
		Passed:           true,
		Sanitizers:       make([]DetectedSanitizer, 0),
		Mutations:        make([]VariantMutation, 0),
		AdjacentBypasses: make([]AdjacentBranchBypass, 0),
		Violations:       make([]Violation, 0),
	}

	for _, fd := range fileDiffs {
		if fd.IsDeleted {
			continue
		}

		filePath := fd.NewPath
		if filePath == "" {
			filePath = fd.OldPath
		}

		// 1. Detect newly introduced sanitizers in added lines
		sanitizersInFile := detectSanitizersInFile(fd, filePath)
		result.Sanitizers = append(result.Sanitizers, sanitizersInFile...)

		// 2. Check for Incomplete Quote Stripping (PatchSlop detection)
		checkIncompleteQuoteStripping(fd, filePath, sanitizersInFile, result)

		// 3. Detect CFG Adjacent Branch Bypasses
		adjacentBypasses := detectAdjacentBranchBypasses(fd, filePath)
		for _, bypass := range adjacentBypasses {
			result.AdjacentBypasses = append(result.AdjacentBypasses, bypass)
			result.Passed = false
			result.Violations = append(result.Violations, Violation{
				RuleID:   RuleAdjacentBranchBypass,
				RuleName: "AdjacentBranchBypass",
				Severity: SeverityHigh,
				File:     bypass.File,
				Line:     bypass.Line,
				Function: bypass.Function,
				Message:  bypass.Description,
				Metadata: map[string]string{
					"branch": bypass.BranchName,
				},
			})
		}
	}

	// 4. Generate Adversarial Variant Mutations from detected sanitizers or diff contexts
	result.Mutations = GenerateAdversarialMutations(result.Sanitizers)
	result.TotalVariants = len(result.Mutations)

	// Format human-readable summary
	result.Summary = formatVariantSummary(result)

	return result, nil
}

// detectSanitizersInFile inspects added lines in a FileDiff for sanitizers, string replacements, regexes, and checks.
func detectSanitizersInFile(fd *FileDiff, filePath string) []DetectedSanitizer {
	var sanitizers []DetectedSanitizer

	for lineNum, lineContent := range fd.AddedLines {
		trimmed := strings.TrimSpace(lineContent)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		kind := ""
		if rxStringReplace.MatchString(trimmed) {
			kind = "string_replace"
		} else if rxRegexCompile.MatchString(trimmed) {
			kind = "regex"
		} else if rxFilterCheck.MatchString(trimmed) {
			kind = "char_filter"
		} else if rxBranchCond.MatchString(trimmed) && (strings.Contains(trimmed, `"`) || strings.Contains(trimmed, `'`)) {
			kind = "branch_condition"
		}

		if kind == "" {
			continue
		}

		isDbl := containsDoubleQuoteTarget(trimmed)
		isSgl := containsSingleQuoteTarget(trimmed)

		targetChar := ""
		if isDbl && isSgl {
			targetChar = `"'`
		} else if isDbl {
			targetChar = `"`
		} else if isSgl {
			targetChar = `'`
		} else if strings.Contains(trimmed, "<script") || strings.Contains(trimmed, "<") {
			targetChar = `<script>`
		} else if strings.Contains(trimmed, "../") || strings.Contains(trimmed, "..\\") {
			targetChar = `../`
		}

		sanitizers = append(sanitizers, DetectedSanitizer{
			File:          filePath,
			Line:          lineNum,
			Snippet:       trimmed,
			Kind:          kind,
			TargetChar:    targetChar,
			IsDoubleQuote: isDbl,
			IsSingleQuote: isSgl,
			IsRegex:       kind == "regex",
			IsBranch:      kind == "branch_condition",
		})
	}

	return sanitizers
}

// containsDoubleQuoteTarget checks if the snippet targets double quotes.
func containsDoubleQuoteTarget(snippet string) bool {
	return strings.Contains(snippet, `\"`) ||
		strings.Contains(snippet, `"\""`) ||
		strings.Contains(snippet, `'"'`) ||
		strings.Contains(snippet, `["']`) ||
		strings.Contains(snippet, `["]`) ||
		strings.Contains(snippet, `"`) && !strings.Contains(snippet, `'`)
}

// containsSingleQuoteTarget checks if the snippet targets single quotes.
func containsSingleQuoteTarget(snippet string) bool {
	return strings.Contains(snippet, `\'`) ||
		strings.Contains(snippet, `'\''`) ||
		strings.Contains(snippet, `"'"`) ||
		strings.Contains(snippet, `["']`) ||
		strings.Contains(snippet, `[']`) ||
		strings.Contains(snippet, `'`) && !strings.Contains(snippet, `"`)
}

// checkIncompleteQuoteStripping checks if a patch strips or filters double quotes but fails to handle single quotes, or vice-versa.
func checkIncompleteQuoteStripping(fd *FileDiff, filePath string, sanitizers []DetectedSanitizer, result *VariantHunterResult) {
	hasDoubleQuoteSanitizer := false
	hasSingleQuoteSanitizer := false
	var doubleQuoteSanitizer DetectedSanitizer
	var singleQuoteSanitizer DetectedSanitizer

	for _, s := range sanitizers {
		if s.IsDoubleQuote && !s.IsSingleQuote {
			hasDoubleQuoteSanitizer = true
			doubleQuoteSanitizer = s
		}
		if s.IsSingleQuote && !s.IsDoubleQuote {
			hasSingleQuoteSanitizer = true
			singleQuoteSanitizer = s
		}
		if s.IsDoubleQuote && s.IsSingleQuote {
			// Both handled in single regex/expression
			hasDoubleQuoteSanitizer = true
			hasSingleQuoteSanitizer = true
		}
	}

	// Also inspect context lines to see if the complementary quote was handled nearby
	if hasDoubleQuoteSanitizer && !hasSingleQuoteSanitizer {
		if !fileDiffHandlesSingleQuote(fd) {
			result.HasPatchSlop = true
			result.Passed = false
			result.Violations = append(result.Violations, Violation{
				RuleID:      RulePatchSlopIncompleteSanitization,
				RuleName:    "PatchSlopIncompleteQuoteStripping",
				Severity:    SeverityCritical,
				File:        filePath,
				Line:        doubleQuoteSanitizer.Line,
				Message:     fmt.Sprintf("PatchSlop detected: Incomplete quote stripping in %s at line %d. Diff checks double quote (\") but omits complementary single quote ('), leaving injection variants open.", filePath, doubleQuoteSanitizer.Line),
				HeadSnippet: doubleQuoteSanitizer.Snippet,
				ASTNodeType: doubleQuoteSanitizer.Kind,
				Metadata: map[string]string{
					"handled": "double_quote",
					"omitted": "single_quote",
				},
			})
		}
	} else if hasSingleQuoteSanitizer && !hasDoubleQuoteSanitizer {
		if !fileDiffHandlesDoubleQuote(fd) {
			result.HasPatchSlop = true
			result.Passed = false
			result.Violations = append(result.Violations, Violation{
				RuleID:      RulePatchSlopIncompleteSanitization,
				RuleName:    "PatchSlopIncompleteQuoteStripping",
				Severity:    SeverityCritical,
				File:        filePath,
				Line:        singleQuoteSanitizer.Line,
				Message:     fmt.Sprintf("PatchSlop detected: Incomplete quote stripping in %s at line %d. Diff checks single quote (') but omits complementary double quote (\"), leaving injection variants open.", filePath, singleQuoteSanitizer.Line),
				HeadSnippet: singleQuoteSanitizer.Snippet,
				ASTNodeType: singleQuoteSanitizer.Kind,
				Metadata: map[string]string{
					"handled": "single_quote",
					"omitted": "double_quote",
				},
			})
		}
	}
}

func fileDiffHandlesSingleQuote(fd *FileDiff) bool {
	for _, hunk := range fd.Hunks {
		for _, dl := range hunk.Lines {
			if dl.Type == LineRemoved {
				continue
			}
			if containsSingleQuoteTarget(dl.Content) {
				return true
			}
		}
	}
	return false
}

func fileDiffHandlesDoubleQuote(fd *FileDiff) bool {
	for _, hunk := range fd.Hunks {
		for _, dl := range hunk.Lines {
			if dl.Type == LineRemoved {
				continue
			}
			if containsDoubleQuoteTarget(dl.Content) {
				return true
			}
		}
	}
	return false
}

// detectAdjacentBranchBypasses detects parallel execution paths in AST / CFG that bypass the new check.
func detectAdjacentBranchBypasses(fd *FileDiff, filePath string) []AdjacentBranchBypass {
	var bypasses []AdjacentBranchBypass

	// First try AST-based detection if Go file
	if strings.HasSuffix(filePath, ".go") {
		astBypasses := detectGoASTAdjacentBypasses(fd, filePath)
		if len(astBypasses) > 0 {
			return astBypasses
		}
	}

	// Pattern-based CFG analysis across hunks (works for Go, Python, Rust, C, etc.)
	for _, hunk := range fd.Hunks {
		var addedCheckLines []int
		var switchCases []struct {
			line    int
			content string
			isAdded bool
		}
		var ifElseBranches []struct {
			line    int
			content string
			isAdded bool
		}

		for _, dl := range hunk.Lines {
			trimmed := strings.TrimSpace(dl.Content)
			if dl.Type == LineAdded {
				if rxStringReplace.MatchString(trimmed) || rxRegexCompile.MatchString(trimmed) || rxFilterCheck.MatchString(trimmed) {
					addedCheckLines = append(addedCheckLines, dl.NewLine)
				}
			}

			if strings.HasPrefix(trimmed, "case ") || strings.HasPrefix(trimmed, "default:") {
				switchCases = append(switchCases, struct {
					line    int
					content string
					isAdded bool
				}{line: dl.NewLine, content: trimmed, isAdded: dl.Type == LineAdded})
			} else if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "else if ") || strings.HasPrefix(trimmed, "elif ") || strings.HasPrefix(trimmed, "else {") || trimmed == "else:" {
				ifElseBranches = append(ifElseBranches, struct {
					line    int
					content string
					isAdded bool
				}{line: dl.NewLine, content: trimmed, isAdded: dl.Type == LineAdded})
			}
		}

		// If a check was added, and there are sibling switch cases that do not contain sanitization
		if len(addedCheckLines) > 0 && len(switchCases) > 1 {
			for _, sc := range switchCases {
				// Sibling branch that was not modified with a sanitizer
				if !sc.isAdded && !strings.Contains(sc.content, "default:") {
					bypasses = append(bypasses, AdjacentBranchBypass{
						File:        filePath,
						Line:        sc.line,
						BranchName:  sc.content,
						Description: fmt.Sprintf("CFG adjacent branch bypass detected: parallel case %q in %s at line %d executes without newly introduced sanitizer", sc.content, filePath, sc.line),
					})
				}
			}
		}

		// If a check was added inside an if branch, but an adjacent else/elif exists without sanitization
		if len(addedCheckLines) > 0 && len(ifElseBranches) > 1 {
			for _, br := range ifElseBranches {
				if (strings.HasPrefix(br.content, "else if ") || strings.HasPrefix(br.content, "elif ") || strings.HasPrefix(br.content, "else")) && !br.isAdded {
					bypasses = append(bypasses, AdjacentBranchBypass{
						File:        filePath,
						Line:        br.line,
						BranchName:  br.content,
						Description: fmt.Sprintf("CFG adjacent branch bypass detected: parallel branch %q in %s at line %d executes without newly introduced check", br.content, filePath, br.line),
					})
				}
			}
		}
	}

	return bypasses
}

// detectGoASTAdjacentBypasses builds a synthetic AST from hunk lines to inspect control flow.
func detectGoASTAdjacentBypasses(fd *FileDiff, filePath string) []AdjacentBranchBypass {
	var bypasses []AdjacentBranchBypass

	// Reconstruct the new version of hunk content wrapped in a function if needed
	var buf bytes.Buffer
	buf.WriteString("package p\nfunc _f() {\n")
	lineMap := make(map[int]int) // synthetic line -> original line
	currentSyntheticLine := 3

	for _, hunk := range fd.Hunks {
		for _, dl := range hunk.Lines {
			if dl.Type == LineRemoved {
				continue
			}
			buf.WriteString(dl.Content)
			buf.WriteString("\n")
			lineMap[currentSyntheticLine] = dl.NewLine
			currentSyntheticLine++
		}
	}
	buf.WriteString("\n}\n")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, buf.Bytes(), 0)
	if err != nil {
		return nil
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SwitchStmt:
			// Check if any case has a sanitizer and sibling cases do not
			var caseHasSanitizer []bool
			var caseClauses []*ast.CaseClause

			for _, stmt := range node.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				caseClauses = append(caseClauses, cc)
				hasSan := false
				for _, bStmt := range cc.Body {
					str := fmt.Sprintf("%v", bStmt)
					if rxStringReplace.MatchString(str) || rxFilterCheck.MatchString(str) {
						hasSan = true
						break
					}
				}
				caseHasSanitizer = append(caseHasSanitizer, hasSan)
			}

			// If at least one case has a sanitizer and at least one non-default case does not
			someHave := false
			someLack := false
			for i, has := range caseHasSanitizer {
				if has {
					someHave = true
				} else if len(caseClauses[i].List) > 0 { // non-default
					someLack = true
				}
			}

			if someHave && someLack {
				for i, has := range caseHasSanitizer {
					if !has && len(caseClauses[i].List) > 0 && len(caseClauses[i].Body) > 0 {
						pos := fset.Position(caseClauses[i].Pos())
						origLine := lineMap[pos.Line]
						if origLine == 0 {
							origLine = pos.Line
						}
						bypasses = append(bypasses, AdjacentBranchBypass{
							File:        filePath,
							Line:        origLine,
							BranchName:  "case clause",
							Description: fmt.Sprintf("CFG adjacent branch bypass in Go AST: case at line %d lacks sanitization present in sibling case", origLine),
						})
					}
				}
			}
		}
		return true
	})

	return bypasses
}

// GenerateAdversarialMutations produces a comprehensive matrix of adversarial variant payloads probing:
// 1. Encoding variations: single quote vs double quote
// 2. Double URL encoding (%2522, %2527, %252F, %253C, %253E, %2500)
// 3. Unicode fullwidth quotes and characters (\uFF02, \uFF07, \uFF1C, \uFF1E, \uFF0F, etc.)
// 4. UTF-8 overlong sequences (\xC0\xA2, \xC0\xA7, \xC0\xAF, etc.)
// 5. Null bytes (\x00, %00, \u0000)
func GenerateAdversarialMutations(sanitizers []DetectedSanitizer) []VariantMutation {
	var mutations []VariantMutation
	seen := make(map[string]bool)

	addMut := func(cat MutationCategory, target, payload, desc string) {
		key := fmt.Sprintf("%s:%s", cat, payload)
		if !seen[key] {
			seen[key] = true
			mutations = append(mutations, VariantMutation{
				Category:    cat,
				Target:      target,
				Payload:     payload,
				Description: desc,
			})
		}
	}

	targets := []string{`"`, `'`}
	for _, s := range sanitizers {
		if s.TargetChar != "" && s.TargetChar != `"` && s.TargetChar != `'` {
			targets = append(targets, s.TargetChar)
		}
	}

	// 1. Encoding variations: Single quote vs double quote substitutions
	addMut(MutationQuoteSubstitution, `"`, `'`, "Single quote substitution probing asymmetric quote stripping")
	addMut(MutationQuoteSubstitution, `'`, `"`, "Double quote substitution probing asymmetric quote stripping")
	addMut(MutationQuoteSubstitution, `"`, "`", "Backtick quote substitution probing alternative quoting")
	addMut(MutationQuoteSubstitution, `"`, `' OR '1'='1`, "Single-quote SQL injection payload variant")
	addMut(MutationQuoteSubstitution, `'`, `" OR "1"="1`, "Double-quote SQL injection payload variant")
	addMut(MutationQuoteSubstitution, `"`, `admin'--`, "Single-quote comment termination variant")
	addMut(MutationQuoteSubstitution, `'`, `admin"--`, "Double-quote comment termination variant")

	// 2. Double URL Encoding (%2522, %2527, %252F, etc.)
	addMut(MutationDoubleURLEncoding, `"`, `%2522`, "Double URL encoded double quote (%2522)")
	addMut(MutationDoubleURLEncoding, `'`, `%2527`, "Double URL encoded single quote (%2527)")
	addMut(MutationDoubleURLEncoding, `/`, `%252F`, "Double URL encoded forward slash (%252F)")
	addMut(MutationDoubleURLEncoding, `\`, `%255C`, "Double URL encoded backslash (%255C)")
	addMut(MutationDoubleURLEncoding, `<`, `%253C`, "Double URL encoded less-than (%253C)")
	addMut(MutationDoubleURLEncoding, `>`, `%253E`, "Double URL encoded greater-than (%253E)")
	addMut(MutationDoubleURLEncoding, `\x00`, `%2500`, "Double URL encoded null byte (%2500)")

	// Also single URL encoding benchmarks
	addMut(MutationDoubleURLEncoding, `"`, `%22`, "Standard URL encoded double quote (%22)")
	addMut(MutationDoubleURLEncoding, `'`, `%27`, "Standard URL encoded single quote (%27)")

	// 3. Unicode Fullwidth Quotes & Homoglyphs
	addMut(MutationUnicodeFullwidth, `"`, "\uFF02", "Unicode fullwidth quotation mark (U+FF02)")
	addMut(MutationUnicodeFullwidth, `'`, "\uFF07", "Unicode fullwidth apostrophe (U+FF07)")
	addMut(MutationUnicodeFullwidth, "`", "\uFF40", "Unicode fullwidth grave accent (U+FF40)")
	addMut(MutationUnicodeFullwidth, `<`, "\uFF1C", "Unicode fullwidth less-than sign (U+FF1C)")
	addMut(MutationUnicodeFullwidth, `>`, "\uFF1E", "Unicode fullwidth greater-than sign (U+FF1E)")
	addMut(MutationUnicodeFullwidth, `/`, "\uFF0F", "Unicode fullwidth solidus (U+FF0F)")
	addMut(MutationUnicodeFullwidth, `\`, "\uFF3C", "Unicode fullwidth reverse solidus (U+FF3C)")
	addMut(MutationUnicodeFullwidth, `"`, "\u201C", "Unicode left double quotation mark (U+201C)")
	addMut(MutationUnicodeFullwidth, `"`, "\u201D", "Unicode right double quotation mark (U+201D)")
	addMut(MutationUnicodeFullwidth, `'`, "\u2018", "Unicode left single quotation mark (U+2018)")
	addMut(MutationUnicodeFullwidth, `'`, "\u2019", "Unicode right single quotation mark (U+2019)")

	// 4. UTF-8 Overlong Sequences
	// Overlong 2-byte representations of 7-bit ASCII characters:
	// " (0x22) -> \xC0\xA2
	// ' (0x27) -> \xC0\xA7
	// < (0x3C) -> \xC0\xBC
	// > (0x3E) -> \xC0\xBE
	// / (0x2F) -> \xC0\xAF
	// . (0x2E) -> \xC0\xAE
	// Null (0x00) -> \xC0\x80 (modified UTF-8 null)
	addMut(MutationOverlongUTF8, `"`, string([]byte{0xC0, 0xA2}), "UTF-8 overlong 2-byte sequence for double quote (0xC0 0xA2)")
	addMut(MutationOverlongUTF8, `'`, string([]byte{0xC0, 0xA7}), "UTF-8 overlong 2-byte sequence for single quote (0xC0 0xA7)")
	addMut(MutationOverlongUTF8, `/`, string([]byte{0xC0, 0xAF}), "UTF-8 overlong 2-byte sequence for forward slash (0xC0 0xAF)")
	addMut(MutationOverlongUTF8, `<`, string([]byte{0xC0, 0xBC}), "UTF-8 overlong 2-byte sequence for less-than (0xC0 0xBC)")
	addMut(MutationOverlongUTF8, `>`, string([]byte{0xC0, 0xBE}), "UTF-8 overlong 2-byte sequence for greater-than (0xC0 0xBE)")
	addMut(MutationOverlongUTF8, `.`, string([]byte{0xC0, 0xAE}), "UTF-8 overlong 2-byte sequence for dot (0xC0 0xAE)")
	addMut(MutationOverlongUTF8, `\x00`, string([]byte{0xC0, 0x80}), "UTF-8 overlong 2-byte sequence for null byte (0xC0 0x80)")

	// 5. Null Bytes
	addMut(MutationNullByteInjection, `\x00`, "\x00", "Raw null byte termination (\\x00)")
	addMut(MutationNullByteInjection, `%00`, `%00`, "URL-encoded null byte (%00)")
	addMut(MutationNullByteInjection, `\u0000`, "\u0000", "Unicode null character (\\u0000)")
	addMut(MutationNullByteInjection, `admin\x00`, "admin\x00.png", "Null byte suffix truncation injection")
	addMut(MutationNullByteInjection, `test%00`, "test%00.php", "URL-encoded null byte extension bypass")

	return mutations
}

func formatVariantSummary(res *VariantHunterResult) string {
	var sb strings.Builder
	sb.WriteString("\n=== Soulcaster Anti-PatchSlop Variant Hunter ===\n")
	sb.WriteString(fmt.Sprintf("Status:               %s\n", map[bool]string{true: "PASSED (0 bypasses detected)", false: "FAILED (Bypasses or PatchSlop detected)"}[res.Passed]))
	sb.WriteString(fmt.Sprintf("PatchSlop Detected:   %t\n", res.HasPatchSlop))
	sb.WriteString(fmt.Sprintf("Sanitizers Found:     %d\n", len(res.Sanitizers)))
	sb.WriteString(fmt.Sprintf("Total Mutations:      %d\n", len(res.Mutations)))
	sb.WriteString(fmt.Sprintf("Adjacent CFG Bypasses:%d\n", len(res.AdjacentBypasses)))
	sb.WriteString(fmt.Sprintf("Total Violations:     %d\n", len(res.Violations)))

	if len(res.Violations) > 0 {
		sb.WriteString("\n[VIOLATIONS DETECTED]\n")
		for i, v := range res.Violations {
			sb.WriteString(fmt.Sprintf("  %d. [%s] (%s) %s\n", i+1, v.RuleID, v.Severity, v.Message))
			if v.HeadSnippet != "" {
				sb.WriteString(fmt.Sprintf("     Snippet: %s\n", v.HeadSnippet))
			}
		}
	}

	return sb.String()
}
