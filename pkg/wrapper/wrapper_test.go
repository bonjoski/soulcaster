package wrapper

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/soulcaster/pkg/intoto"
)

func TestWrapperSourceCapture(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock go.mod and source files
	goModContent := "module example.com/testapp\n\ngo 1.27\n"
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	mainGoContent := `package main

import "fmt"

func main() {
	fmt.Println("Soulcaster test binary")
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainGoContent), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	utilGoContent := `package main

func Helper() string {
	return "ok"
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "util.go"), []byte(utilGoContent), 0644); err != nil {
		t.Fatalf("Failed to write util.go: %v", err)
	}

	outBinary := filepath.Join(tempDir, "testapp_bin")
	attestPath := filepath.Join(tempDir, "testapp_bin.intoto.jsonl")

	var stdout, stderr bytes.Buffer

	cfg := Config{
		Command:         []string{"go", "build", "-o", outBinary, "."},
		WorkDir:         tempDir,
		OutputBinary:    outBinary,
		AttestationPath: attestPath,
		Hermetic:        true,
		Version:         "0.1.0",
		Stdout:          &stdout,
		Stderr:          &stderr,
	}

	res, err := Wrap(cfg)
	if err != nil {
		t.Fatalf("Wrap failed: %v, stderr: %s", err, stderr.String())
	}

	if res.OutputBinary != outBinary {
		t.Errorf("Expected output binary %s, got %s", outBinary, res.OutputBinary)
	}

	if len(res.OutputDigest) != 64 {
		t.Errorf("Expected 64-char sha256 output digest, got %q", res.OutputDigest)
	}

	// Verify captured source files count (go.mod, main.go, util.go = 3)
	if res.SourceFilesCaptured < 3 {
		t.Errorf("Expected at least 3 source files captured, got %d", res.SourceFilesCaptured)
	}

	// Verify attestation file exists on disk
	attestBytes, err := os.ReadFile(attestPath)
	if err != nil {
		t.Fatalf("Attestation file was not created: %v", err)
	}

	stmt, err := intoto.ParseStatement(attestBytes)
	if err != nil {
		t.Fatalf("Generated attestation failed parsing: %v", err)
	}

	if stmt.Subject[0].Digest["sha256"] != res.OutputDigest {
		t.Errorf("Attestation subject digest %s does not match wrapper result digest %s",
			stmt.Subject[0].Digest["sha256"], res.OutputDigest)
	}

	// Check that main.go and util.go are in source files list
	foundMain := false
	for _, src := range stmt.Predicate.BuildDefinition.ExternalParameters.SourceFiles {
		if filepath.Base(src.Name) == "main.go" {
			foundMain = true
			expectedHash := GenerateSourceHash([]byte(mainGoContent))
			if src.Digest["sha256"] != expectedHash {
				t.Errorf("main.go hash mismatch: got %s, expected %s", src.Digest["sha256"], expectedHash)
			}
		}
	}

	if !foundMain {
		t.Errorf("main.go was not captured in attestation source files list")
	}
}

func TestWrapperTOCTOUDetection(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(srcFile, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	outBinary := filepath.Join(tempDir, "tampered_app")

	// Create a mock compiler script that writes out a binary but ALSO modifies main.go during build
	scriptContent := `#!/bin/sh
# Generate fake binary
echo "compiled_binary" > "` + outBinary + `"
# Malicious background modification (TOCTOU attack)
echo "// Injected backdoor" >> "` + srcFile + `"
exit 0
`
	scriptPath := filepath.Join(tempDir, "mock_compiler.sh")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to write mock compiler: %v", err)
	}

	cfg := Config{
		Command:      []string{scriptPath},
		WorkDir:      tempDir,
		OutputBinary: outBinary,
		Hermetic:     true,
	}

	_, err := Wrap(cfg)
	if err == nil {
		t.Fatalf("Expected TOCTOU tamper detection error, but Wrap succeeded!")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("TOCTOU violation")) {
		t.Errorf("Expected error to mention TOCTOU violation, got: %v", err)
	}
}
