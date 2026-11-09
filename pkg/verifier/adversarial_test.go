package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/soulcaster/pkg/intoto"
)

func TestAdversarialUnsignedAndWrongKeyRejectedByDefault(t *testing.T) {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "agent")
	if err := os.WriteFile(binPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	binSha, _ := hashFile(binPath)

	now := time.Now().UTC()
	stmt := intoto.NewStatement(
		[]intoto.ResourceDescriptor{{Name: "agent", Digest: intoto.DigestSet{"sha256": binSha}}},
		[]string{"go", "build", "-o", "agent", "."},
		nil, nil,
		intoto.InternalParameters{SoulcasterVersion: "0.1.0", HermeticMode: true},
		&now, &now, "inv-unsigned", nil,
	)

	unsignedPath := filepath.Join(tempDir, "unsigned.intoto.jsonl")
	rawBytes, _ := stmt.ToJSONL()
	if err := os.WriteFile(unsignedPath, rawBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)

	// 1. Unsigned JSON rejected even when trusted key is supplied
	if _, err := Verify(Options{
		AttestationPath: unsignedPath,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		TrustedKeys:     []ed25519.PublicKey{pub1},
	}); err == nil {
		t.Fatal("Expected unsigned raw Statement to be rejected by Verify, but it passed")
	}

	// 2. Missing trusted key without AllowUnsignedDev rejected
	if _, err := Verify(Options{
		AttestationPath: unsignedPath,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
	}); err == nil {
		t.Fatal("Expected Verify without trusted keys to fail closed")
	}

	// 3. Attestation signed by attacker key (priv2) rejected against pub1
	_, attackerSigned, err := intoto.SignStatementDSSE(stmt, priv2)
	if err != nil {
		t.Fatal(err)
	}
	forgedPath := filepath.Join(tempDir, "forged.intoto.jsonl")
	if err := os.WriteFile(forgedPath, attackerSigned, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Options{
		AttestationPath: forgedPath,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		TrustedKeys:     []ed25519.PublicKey{pub1},
	}); err == nil {
		t.Fatal("Expected DSSE signed by untrusted key to be rejected")
	}
}

func TestAdversarialVerifySourcesFailsClosedOnMissingTraversalAndUntracked(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "app")
	if err := os.WriteFile(binPath, []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	binSha, _ := hashFile(binPath)

	srcPath := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(srcPath, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	srcSha, _ := hashFile(srcPath)

	writeSigned := func(sources []intoto.ResourceDescriptor) string {
		now := time.Now().UTC()
		stmt := intoto.NewStatement(
			[]intoto.ResourceDescriptor{{Name: "app", Digest: intoto.DigestSet{"sha256": binSha}}},
			[]string{"go", "build", "-o", "app", "."},
			sources, nil,
			intoto.InternalParameters{SoulcasterVersion: "0.1.0", HermeticMode: true},
			&now, &now, "inv-adv", nil,
		)
		_, signedBytes, sErr := intoto.SignStatementDSSE(stmt, priv)
		if sErr != nil {
			t.Fatal(sErr)
		}
		p := filepath.Join(tempDir, "app.intoto.jsonl")
		if wErr := os.WriteFile(p, signedBytes, 0600); wErr != nil {
			t.Fatal(wErr)
		}
		return p
	}

	// Case 1: Path traversal in src.Name ("../outside.go") must fail closed
	outsideFile := filepath.Join(t.TempDir(), "outside.go")
	if err := os.WriteFile(outsideFile, []byte("package outside\n"), 0644); err != nil {
		t.Fatal(err)
	}
	outSha, _ := hashFile(outsideFile)
	relEscape, _ := filepath.Rel(tempDir, outsideFile)
	attestTraversal := writeSigned([]intoto.ResourceDescriptor{
		{Name: filepath.ToSlash(relEscape), Digest: intoto.DigestSet{"sha256": outSha}},
	})
	if _, err := Verify(Options{
		AttestationPath: attestTraversal,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		VerifySources:   true,
		TrustedKeys:     []ed25519.PublicKey{pub},
	}); err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("Expected path traversal in src.Name to fail closed, got: %v", err)
	}

	// Case 2: Deleted attested source file on disk must fail closed (previously silently skipped!)
	attestValid := writeSigned([]intoto.ResourceDescriptor{
		{Name: "main.go", Digest: intoto.DigestSet{"sha256": srcSha}},
	})
	if err := os.Remove(srcPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Options{
		AttestationPath: attestValid,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		VerifySources:   true,
		TrustedKeys:     []ed25519.PublicKey{pub},
	}); err == nil || !strings.Contains(err.Error(), "missing on disk") {
		t.Fatalf("Expected deleted attested source file to fail closed, got: %v", err)
	}

	// Restore main.go, then add an unattested rogue.go -> must fail closed
	if err := os.WriteFile(srcPath, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "rogue_init.go"), []byte("package main\nfunc init() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Options{
		AttestationPath: attestValid,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		VerifySources:   true,
		TrustedKeys:     []ed25519.PublicKey{pub},
	}); err == nil || !strings.Contains(err.Error(), "unattested source file") {
		t.Fatalf("Expected unattested source file to fail closed, got: %v", err)
	}
}
