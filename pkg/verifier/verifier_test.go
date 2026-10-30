package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/soulcaster/pkg/intoto"
)

func TestVerifierTamperedBinaryDetection(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create original binary
	binPath := filepath.Join(tempDir, "production_agent")
	originalBytes := []byte("\x7fELF\x02\x01\x01\x00_secure_binary_payload_")
	if err := os.WriteFile(binPath, originalBytes, 0755); err != nil {
		t.Fatalf("Failed to write binary: %v", err)
	}

	actualSha, err := hashFile(binPath)
	if err != nil {
		t.Fatalf("Failed to hash binary: %v", err)
	}

	// 2. Generate valid SLSA attestation
	now := time.Now().UTC()
	subject := []intoto.ResourceDescriptor{
		{
			Name: "production_agent",
			URI:  "file://production_agent",
			Digest: intoto.DigestSet{
				"sha256": actualSha,
			},
		},
	}
	stmt := intoto.NewStatement(
		subject,
		[]string{"go", "build", "-o", "production_agent", "."},
		[]intoto.ResourceDescriptor{
			{Name: "main.go", Digest: intoto.DigestSet{"sha256": "12345"}},
		},
		map[string]string{"GOOS": "linux"},
		intoto.InternalParameters{SoulcasterVersion: "0.1.0", HermeticMode: true},
		&now,
		&now,
		"inv-test",
		nil,
	)

	attestPath := filepath.Join(tempDir, "production_agent.intoto.jsonl")
	data, err := stmt.ToJSONL()
	if err != nil {
		t.Fatalf("Failed to marshal attestation: %v", err)
	}
	if err := os.WriteFile(attestPath, data, 0644); err != nil {
		t.Fatalf("Failed to write attestation: %v", err)
	}

	// 3. Verify pristine binary passes
	opts := Options{
		AttestationPath: attestPath,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		VerifySources:   false,
	}

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Expected pristine binary verification to pass, got: %v", err)
	}
	if !res.Passed {
		t.Errorf("Expected res.Passed == true")
	}

	// 4. Tamper with the binary (flip bytes)
	tamperedBytes := []byte("\x7fELF\x02\x01\x01\x00_backdoored_payload_")
	if err := os.WriteFile(binPath, tamperedBytes, 0755); err != nil {
		t.Fatalf("Failed to overwrite binary with tampered payload: %v", err)
	}

	// 5. Verify tampered binary is detected and rejected
	resTampered, err := Verify(opts)
	if err == nil {
		t.Fatalf("Expected tampered binary verification to FAIL, but it succeeded!")
	}
	if resTampered != nil && resTampered.Passed {
		t.Errorf("Expected resTampered.Passed == false")
	}
	if !strings.Contains(err.Error(), "tampered with or modified") {
		t.Errorf("Expected tamper error message, got: %v", err)
	}
}

func TestVerifierSourceVerification(t *testing.T) {
	tempDir := t.TempDir()

	binPath := filepath.Join(tempDir, "app")
	if err := os.WriteFile(binPath, []byte("app_content"), 0755); err != nil {
		t.Fatalf("Failed to write binary: %v", err)
	}
	binSha, _ := hashFile(binPath)

	srcPath := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(srcPath, []byte("package main\n"), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}
	srcSha, _ := hashFile(srcPath)

	now := time.Now().UTC()
	stmt := intoto.NewStatement(
		[]intoto.ResourceDescriptor{
			{Name: "app", Digest: intoto.DigestSet{"sha256": binSha}},
		},
		[]string{"go", "build", "-o", "app", "."},
		[]intoto.ResourceDescriptor{
			{Name: "main.go", Digest: intoto.DigestSet{"sha256": srcSha}},
		},
		nil,
		intoto.InternalParameters{SoulcasterVersion: "0.1.0"},
		&now, &now, "inv-src", nil,
	)
	attestPath := filepath.Join(tempDir, "app.intoto.jsonl")
	data, _ := stmt.ToJSONL()
	os.WriteFile(attestPath, data, 0644)

	// Untouched source -> passes
	res, err := Verify(Options{
		AttestationPath: attestPath,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		VerifySources:   true,
	})
	if err != nil || !res.Passed {
		t.Fatalf("Expected source verification to pass, got: %v", err)
	}
	if res.SourceFilesVerified != 1 {
		t.Errorf("Expected 1 verified source file, got %d", res.SourceFilesVerified)
	}

	// Tamper with source file on disk
	os.WriteFile(srcPath, []byte("package main // altered"), 0644)

	resTampered, err := Verify(Options{
		AttestationPath: attestPath,
		BinaryPath:      binPath,
		WorkDir:         tempDir,
		VerifySources:   true,
	})
	if err == nil {
		t.Fatalf("Expected source tampering to fail verification!")
	}
	if resTampered.Passed {
		t.Errorf("Expected resTampered.Passed == false")
	}
}
