package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/soulcaster/pkg/intoto"
	"github.com/bonjoski/soulcaster/pkg/ux"
)

func TestSoulcasterExplain_AllTopicsAndFlags(t *testing.T) {
	topics := []string{"receipt", "slsa", "toctou", "verify-patch"}

	for _, topic := range topics {
		t.Run(topic+"/default", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q) exit=%d stderr=%s", topic, code, errBuf.String())
			}
			rendered := out.String()
			if strings.ContainsRune(rendered, 0x1b) {
				t.Fatalf("explain output contains raw ESC: %q", rendered)
			}
			lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
			if len(lines) > 3 {
				t.Fatalf("default explain(%q) exceeded 3 lines (%d):\n%s", topic, len(lines), rendered)
			}
		})

		t.Run(topic+"/why", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic, "--why"}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q, --why) exit=%d", topic, code)
			}
			if !strings.Contains(out.String(), "Deep Dive (--why):") {
				t.Fatalf("expected Deep Dive (--why) for %q", topic)
			}
		})

		t.Run(topic+"/json", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic, "--json"}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q, --json) exit=%d", topic, code)
			}
			var decoded ux.FixForwardError
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatalf("invalid JSON for %q: %v", topic, err)
			}
			if decoded.Tool != "soulcaster" || decoded.Code == "" || decoded.Summary == "" || decoded.RemediationCmd == "" || decoded.WhyOneLiner == "" {
				t.Fatalf("incomplete FixForwardError JSON for %q: %+v", topic, decoded)
			}
		})
	}
}

func TestSoulcasterReceiptCLI_EndToEndAndErrors(t *testing.T) {
	tmp := t.TempDir()
	art := filepath.Join(tmp, "demo-bin")
	if err := os.WriteFile(art, []byte("hello-slsa-v1"), 0755); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	// 1. --json emits valid in-toto / SLSA v1.0 statement to stdout
	var out, errBuf bytes.Buffer
	code := runReceipt([]string{"--artifact", art, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runReceipt --json exit=%d stderr=%s", code, errBuf.String())
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Fatalf("receipt JSON contains raw ESC")
	}
	stmt, err := intoto.ParseStatement(bytes.TrimSpace(out.Bytes()))
	if err != nil {
		t.Fatalf("receipt JSON failed intoto.ParseStatement: %v", err)
	}
	if stmt.PredicateType != intoto.SLSAPredicateTypeV1 {
		t.Fatalf("unexpected predicateType: %q", stmt.PredicateType)
	}

	// 2. --out with calm default output (<=3 lines)
	out.Reset()
	errBuf.Reset()
	receiptFile := filepath.Join(tmp, "receipts", "provenance.intoto.jsonl")
	code = runReceipt([]string{"--artifact", art, "--out", receiptFile}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runReceipt --out exit=%d stderr=%s", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("default receipt output exceeded 3 lines (%d):\n%s", len(lines), out.String())
	}

	// 3. --why expands deep dive
	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"--artifact", art, "--out", receiptFile, "--why"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runReceipt --why exit=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") {
		t.Fatalf("expected Deep Dive (--why) in receipt output:\n%s", out.String())
	}

	// 4. Symlink artifact returns FixForwardError JSON with exit 1
	sym := filepath.Join(tmp, "evil-link")
	if err := os.Symlink(art, sym); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"--artifact", sym, "--json"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("expected symlink receipt exit 1, got %d", code)
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("symlink error stderr invalid JSON: %v (raw: %q)", err, errBuf.String())
	}
	if ffe.Code != "SOULCASTER_RECEIPT_SYMLINK_REJECTED" || ffe.RemediationCmd == "" || ffe.WhyOneLiner == "" {
		t.Fatalf("unexpected FixForwardError for symlink: %+v", ffe)
	}

	// 5. Missing --artifact returns FixForwardError JSON with exit 1
	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"--json"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("expected missing artifact exit 1, got %d", code)
	}
	var missingFFE ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &missingFFE); err != nil {
		t.Fatalf("missing artifact stderr invalid JSON: %v", err)
	}
	if missingFFE.Code != "SOULCASTER_RECEIPT_MISSING_ARTIFACT" {
		t.Fatalf("unexpected code: %+v", missingFFE)
	}
}
