package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/soulcaster/pkg/intoto"
)

func TestGenerateAndVerifyReceipt_LocalSLSACompatibility(t *testing.T) {
	tmp := t.TempDir()
	artifactPath := filepath.Join(tmp, "myapp")
	payload := []byte("deterministic-binary-contents-v1")
	if err := os.WriteFile(artifactPath, payload, 0755); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	expectedSum := sha256.Sum256(payload)
	expectedHex := hex.EncodeToString(expectedSum[:])

	outPath := filepath.Join(tmp, "receipts", "provenance.intoto.jsonl")
	res, err := Generate(Options{
		ArtifactPath: artifactPath,
		OutputPath:   outPath,
		WorkDir:      tmp,
		Version:      "0.4.0-test",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if res.SHA256 != expectedHex {
		t.Fatalf("SHA256 mismatch: got %s, want %s", res.SHA256, expectedHex)
	}

	// Verify file on disk is single-line JSONL compatible with verify-local-receipts.yml
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read receipt file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected single-line JSONL receipt for CI workflow compatibility, got %d lines", len(lines))
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &doc); err != nil {
		t.Fatalf("invalid JSON in receipt: %v", err)
	}
	if got := doc["_type"]; got != intoto.StatementTypeV1 {
		t.Fatalf("unexpected _type: %v", got)
	}
	if got := doc["predicateType"]; got != intoto.SLSAPredicateTypeV1 {
		t.Fatalf("unexpected predicateType: %v", got)
	}

	// Verify ParseStatement and VerifyReceipt both succeed
	stmt, err := VerifyReceipt(outPath, artifactPath)
	if err != nil {
		t.Fatalf("VerifyReceipt failed on untampered artifact: %v", err)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Digest["sha256"] != expectedHex {
		t.Fatalf("unexpected subject in verified receipt: %+v", stmt.Subject)
	}
	if stmt.Predicate.RunDetails.Builder.ID != intoto.SoulcasterBuilderID {
		t.Fatalf("unexpected builder ID: %q", stmt.Predicate.RunDetails.Builder.ID)
	}
	if stmt.Predicate.RunDetails.Metadata.FinishedOn == nil {
		t.Fatalf("expected build timestamp in receipt metadata")
	}
}

func TestVerifyReceipt_DetectsTamperDigestMismatch(t *testing.T) {
	tmp := t.TempDir()
	artifactPath := filepath.Join(tmp, "service")
	if err := os.WriteFile(artifactPath, []byte("original-build-v1"), 0755); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	outPath := filepath.Join(tmp, "provenance.intoto.jsonl")
	if _, err := Generate(Options{
		ArtifactPath: artifactPath,
		OutputPath:   outPath,
		WorkDir:      tmp,
		Version:      "0.4.0-test",
	}); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Tamper with the artifact post-receipt
	if err := os.WriteFile(artifactPath, []byte("tampered-build-v1"), 0755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	_, err := VerifyReceipt(outPath, artifactPath)
	if err == nil {
		t.Fatalf("expected VerifyReceipt to fail on tampered artifact, got nil")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got: %v", err)
	}
}

func TestGenerateReceipt_RejectsSymlinkArtifactAndOutput(t *testing.T) {
	tmp := t.TempDir()
	realFile := filepath.Join(tmp, "real-secret.txt")
	if err := os.WriteFile(realFile, []byte("sensitive-host-file"), 0600); err != nil {
		t.Fatalf("write real file: %v", err)
	}

	symlinkArtifact := filepath.Join(tmp, "app-link")
	if err := os.Symlink(realFile, symlinkArtifact); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// 1. Symlink artifact must be rejected fail-closed
	_, err := Generate(Options{
		ArtifactPath: symlinkArtifact,
		WorkDir:      tmp,
		Version:      "0.4.0-test",
	})
	if err == nil {
		t.Fatalf("expected symlink artifact to be rejected, got nil")
	}
	if !errors.Is(err, ErrSymlinkArtifact) {
		t.Fatalf("expected ErrSymlinkArtifact, got: %v", err)
	}

	// 2. Symlink output path must also be rejected fail-closed
	regularArtifact := filepath.Join(tmp, "real-app")
	if err := os.WriteFile(regularArtifact, []byte("binary"), 0755); err != nil {
		t.Fatalf("write regular artifact: %v", err)
	}
	symlinkOut := filepath.Join(tmp, "out-link.intoto.jsonl")
	if err := os.Symlink(realFile, symlinkOut); err != nil {
		t.Fatalf("create output symlink: %v", err)
	}

	_, err = Generate(Options{
		ArtifactPath: regularArtifact,
		OutputPath:   symlinkOut,
		WorkDir:      tmp,
		Version:      "0.4.0-test",
	})
	if err == nil {
		t.Fatalf("expected symlink output path to be rejected, got nil")
	}
	if !errors.Is(err, ErrSymlinkArtifact) {
		t.Fatalf("expected ErrSymlinkArtifact for output symlink, got: %v", err)
	}
	// Ensure symlink target was untouched
	gotTarget, _ := os.ReadFile(realFile)
	if !bytes.Equal(gotTarget, []byte("sensitive-host-file")) {
		t.Fatalf("symlink output target was clobbered!")
	}
}

func TestGenerateReceipt_RejectsDirectoryArtifact(t *testing.T) {
	tmp := t.TempDir()
	_, err := Generate(Options{
		ArtifactPath: tmp,
		WorkDir:      tmp,
	})
	if err == nil {
		t.Fatalf("expected directory artifact to be rejected")
	}
	if !errors.Is(err, ErrNonRegularArtifact) {
		t.Fatalf("expected ErrNonRegularArtifact, got: %v", err)
	}
}

func TestGenerateReceipt_ZeroRawANSIEscapes(t *testing.T) {
	tmp := t.TempDir()
	// Hostile filename containing ESC sequence
	weirdName := "app-\x1b[31mred\x1b[0m-bin"
	artifactPath := filepath.Join(tmp, weirdName)
	if err := os.WriteFile(artifactPath, []byte("binary"), 0755); err != nil {
		t.Skipf("filesystem rejected ESC in filename: %v", err)
	}

	res, err := Generate(Options{
		ArtifactPath: artifactPath,
		WorkDir:      tmp,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if bytes.ContainsRune(res.JSONL, 0x1b) {
		t.Fatalf("generated receipt JSONL contains raw ESC byte: %q", string(res.JSONL))
	}
	if strings.Contains(string(res.JSONL), "[31m") {
		t.Fatalf("generated receipt JSONL contains CSI fragment: %q", string(res.JSONL))
	}
}
