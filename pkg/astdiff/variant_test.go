package astdiff

import (
	"strings"
	"testing"
)

func TestDetectIncompleteQuoteStrippingPatchSlop(t *testing.T) {
	// Patch adds double-quote stripping only, completely forgetting single quote
	patchDiff := `diff --git a/pkg/query/sanitize.go b/pkg/query/sanitize.go
index 1111111..2222222 100644
--- a/pkg/query/sanitize.go
+++ b/pkg/query/sanitize.go
@@ -10,6 +10,7 @@ func SanitizeInput(input string) string {
 	// Strip dangerous characters
+	input = strings.ReplaceAll(input, "\"", "")
 	return input
 }
`

	result, err := AnalyzePatchVariants([]byte(patchDiff))
	if err != nil {
		t.Fatalf("AnalyzePatchVariants failed: %v", err)
	}

	if result.Passed {
		t.Errorf("Expected analysis to FAIL due to PatchSlop incomplete quote stripping, but it passed")
	}

	if !result.HasPatchSlop {
		t.Errorf("Expected HasPatchSlop == true, got false")
	}

	foundRule := false
	for _, v := range result.Violations {
		if v.RuleID == RulePatchSlopIncompleteSanitization {
			foundRule = true
			if !strings.Contains(v.Message, "Incomplete quote stripping") {
				t.Errorf("Unexpected violation message: %s", v.Message)
			}
		}
	}

	if !foundRule {
		t.Errorf("Expected RulePatchSlopIncompleteSanitization violation to be emitted")
	}
}

func TestCompleteQuoteStrippingPasses(t *testing.T) {
	// Patch handles both double and single quotes
	patchDiff := `diff --git a/pkg/query/sanitize.go b/pkg/query/sanitize.go
index 1111111..2222222 100644
--- a/pkg/query/sanitize.go
+++ b/pkg/query/sanitize.go
@@ -10,6 +10,8 @@ func SanitizeInput(input string) string {
 	// Strip dangerous characters
+	input = strings.ReplaceAll(input, "\"", "")
+	input = strings.ReplaceAll(input, "'", "")
 	return input
 }
`

	result, err := AnalyzePatchVariants([]byte(patchDiff))
	if err != nil {
		t.Fatalf("AnalyzePatchVariants failed: %v", err)
	}

	if result.HasPatchSlop {
		t.Errorf("Expected complete quote stripping to not trigger HasPatchSlop")
	}
}

func TestAdversarialMutationCoverage(t *testing.T) {
	sanitizers := []DetectedSanitizer{
		{
			File:       "sanitize.go",
			Line:       12,
			Snippet:    `input = strings.ReplaceAll(input, "\"", "")`,
			Kind:       "string_replace",
			TargetChar: `"`,
		},
	}

	mutations := GenerateAdversarialMutations(sanitizers)
	if len(mutations) == 0 {
		t.Fatalf("Expected non-empty variant mutations list")
	}

	categories := make(map[MutationCategory]bool)
	hasSingleQuote := false
	hasDoubleURLEncoding := false
	hasUnicodeFullwidth := false
	hasOverlongUTF8 := false
	hasNullByte := false

	for _, m := range mutations {
		categories[m.Category] = true
		if m.Payload == `'` || m.Payload == `" OR "1"="1` || m.Payload == `' OR '1'='1` {
			hasSingleQuote = true
		}
		if m.Payload == `%2522` || m.Payload == `%2527` {
			hasDoubleURLEncoding = true
		}
		if m.Payload == "\uFF02" || m.Payload == "\uFF07" {
			hasUnicodeFullwidth = true
		}
		if len(m.Payload) == 2 && m.Payload[0] == 0xC0 && m.Payload[1] == 0xA2 {
			hasOverlongUTF8 = true
		}
		if m.Payload == "\x00" || m.Payload == "%00" {
			hasNullByte = true
		}
	}

	if !hasSingleQuote {
		t.Errorf("Missing single quote mutation")
	}
	if !hasDoubleURLEncoding {
		t.Errorf("Missing double URL encoding (%%2522) mutation")
	}
	if !hasUnicodeFullwidth {
		t.Errorf("Missing unicode fullwidth (\\uFF02) mutation")
	}
	if !hasOverlongUTF8 {
		t.Errorf("Missing overlong UTF-8 (\\xC0\\xA2) mutation")
	}
	if !hasNullByte {
		t.Errorf("Missing null byte (\\x00) mutation")
	}
}

func TestAdjacentBranchDetection(t *testing.T) {
	// Patch adds sanitization only to case "A", leaving case "B" unhandled
	patchDiff := `diff --git a/pkg/handler/dispatch.go b/pkg/handler/dispatch.go
index 1111111..2222222 100644
--- a/pkg/handler/dispatch.go
+++ b/pkg/handler/dispatch.go
@@ -15,8 +15,9 @@ func Dispatch(action string, payload string) {
 	switch action {
 	case "view":
+		payload = strings.ReplaceAll(payload, "\"", "")
 		render(payload)
 	case "export":
 		render(payload)
 	}
 }
`

	result, err := AnalyzePatchVariants([]byte(patchDiff))
	if err != nil {
		t.Fatalf("AnalyzePatchVariants failed: %v", err)
	}

	if len(result.AdjacentBypasses) == 0 {
		t.Errorf("Expected adjacent branch bypass to be detected for case 'export'")
	}

	foundViolation := false
	for _, v := range result.Violations {
		if v.RuleID == RuleAdjacentBranchBypass {
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Errorf("Expected RuleAdjacentBranchBypass violation")
	}
}
