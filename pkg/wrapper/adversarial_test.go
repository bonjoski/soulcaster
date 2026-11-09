package wrapper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/soulcaster/pkg/intoto"
)

func TestAdversarialSignFailsClosedWithoutKey(t *testing.T) {
	t.Setenv("SOULCASTER_SIGNING_KEY", "")
	tempDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module example.com/app\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	outBin := filepath.Join(tempDir, "app")
	attestPath := filepath.Join(tempDir, "app.intoto.jsonl")

	_, err := Wrap(Config{
		Command:         []string{"go", "build", "-o", outBin, "."},
		WorkDir:         tempDir,
		OutputBinary:    outBin,
		AttestationPath: attestPath,
		Hermetic:        true,
		Sign:            true,
	})
	if err == nil {
		t.Fatal("Expected Wrap with Sign=true and no key to fail closed, but it succeeded")
	}
	if _, statErr := os.Stat(attestPath); !os.IsNotExist(statErr) {
		t.Fatal("Unsigned attestation file was emitted on disk despite missing signing key")
	}
}

func TestAdversarialSignedDSSEWrapAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module example.com/signed\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	vendorDir := filepath.Join(tempDir, "vendor", "example.com", "dep")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "dep.go"), []byte("package dep\n"), 0644); err != nil {
		t.Fatal(err)
	}

	outBin := filepath.Join(tempDir, "signed_bin")
	attestPath := filepath.Join(tempDir, "signed_bin.intoto.jsonl")
	var stdout, stderr bytes.Buffer

	res, err := Wrap(Config{
		Command:         []string{"go", "build", "-o", outBin, "."},
		WorkDir:         tempDir,
		OutputBinary:    outBin,
		AttestationPath: attestPath,
		Hermetic:        true,
		Sign:            true,
		SigningKey:      hex.EncodeToString(priv.Seed()),
		Stdout:          &stdout,
		Stderr:          &stderr,
	})
	if err != nil {
		t.Fatalf("Signed Wrap failed: %v (stderr: %s)", err, stderr.String())
	}
	if !res.Signed || res.Envelope == nil {
		t.Fatalf("Expected signed DSSE result")
	}

	raw, err := os.ReadFile(attestPath)
	if err != nil {
		t.Fatal(err)
	}
	stmt, keyID, err := intoto.VerifyDSSE(raw, pub)
	if err != nil {
		t.Fatalf("VerifyDSSE failed: %v", err)
	}
	if keyID != res.KeyID {
		t.Errorf("KeyID mismatch: got %q, want %q", keyID, res.KeyID)
	}

	foundVendor := false
	for _, src := range stmt.Predicate.BuildDefinition.ExternalParameters.SourceFiles {
		if src.Name == "vendor/example.com/dep/dep.go" {
			foundVendor = true
		}
	}
	if !foundVendor {
		t.Errorf("Expected vendor/example.com/dep/dep.go to be captured in sourceFiles")
	}

	// Verify externalSocketsDetected is NOT falsely claimed as "0" when NetworkIsolated is false
	if len(stmt.Predicate.RunDetails.Byproducts) == 0 ||
		stmt.Predicate.RunDetails.Byproducts[0].Annotations["externalSocketsDetected"] == "0" {
		t.Errorf("Expected externalSocketsDetected not to claim '0' without verified sandbox isolation")
	}
}

func TestAdversarialCompilerFlagSmugglingBlocked(t *testing.T) {
	tempDir := t.TempDir()
	outBin := filepath.Join(tempDir, "out")

	blockedCommands := [][]string{
		{"go", "build", "-overlay", "/tmp/evil.json", "-o", outBin, "."},
		{"go", "build", "-overlay=/tmp/evil.json", "-o", outBin, "."},
		{"go", "build", "-toolexec=/tmp/hijack.sh", "-o", outBin, "."},
		{"go", "build", "--modfile=evil.mod", "-o", outBin, "."},
		{"go", "build", "-gcflags=-N", "-o", outBin, "."},
		{"go", "build", "-ldflags", "-extld=/tmp/evil-ld", "-o", outBin, "."},
		{"cargo", "build", "--config", "build.rustc-wrapper='/tmp/evil'", "--output", outBin},
		{"rustc", "-C", "linker=/tmp/evil", "-o", outBin, "main.rs"},
	}

	for _, cmdArgs := range blockedCommands {
		_, err := Wrap(Config{
			Command:      cmdArgs,
			WorkDir:      tempDir,
			OutputBinary: outBin,
			Hermetic:     true,
		})
		if err == nil {
			t.Errorf("Expected smuggling command %v to be blocked, but Wrap succeeded", cmdArgs)
		}
	}
}

func TestAdversarialCleanRoomEnvironmentScrubbing(t *testing.T) {
	t.Setenv("GOFLAGS", "-overlay=/tmp/nonexistent-overlay.json")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
	t.Setenv("RUSTC_WRAPPER", "/tmp/evil_rustc")
	t.Setenv("CC", "/tmp/evil_cc")
	t.Setenv("SOULCASTER_SIGNING_KEY", "secret_should_not_leak")

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	outBin := filepath.Join(tempDir, "env_dump_bin")
	envDump := filepath.Join(tempDir, "child_env.log")
	script := "#!/bin/sh\nenv > \"" + envDump + "\"\necho bin > \"" + outBin + "\"\n"
	scriptPath := filepath.Join(tempDir, "check_env.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	_, err := Wrap(Config{
		Command:      []string{scriptPath},
		WorkDir:      tempDir,
		OutputBinary: outBin,
		Hermetic:     true,
	})
	if err != nil {
		t.Fatalf("Wrap failed: %v", err)
	}

	dumpedBytes, err := os.ReadFile(envDump)
	if err != nil {
		t.Fatal(err)
	}
	dumped := string(dumpedBytes)
	for _, forbidden := range []string{
		"GOFLAGS=",
		"LD_PRELOAD=",
		"DYLD_INSERT_LIBRARIES=",
		"RUSTC_WRAPPER=",
		"CC=",
		"SOULCASTER_SIGNING_KEY=",
	} {
		if strings.Contains(dumped, forbidden) {
			t.Errorf("Forbidden env var %q leaked into compiler child process:\n%s", forbidden, dumped)
		}
	}
	if !strings.Contains(dumped, "GOPROXY=off") || !strings.Contains(dumped, "GOCACHE=") {
		t.Errorf("Expected GOPROXY=off and isolated GOCACHE in child env, got:\n%s", dumped)
	}
}

func TestAdversarialSymlinkEscapeRejected(t *testing.T) {
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "secret.go")
	if err := os.WriteFile(secretFile, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	workDir := t.TempDir()
	if err := os.Symlink(secretFile, filepath.Join(workDir, "escaped.go")); err != nil {
		t.Fatal(err)
	}

	_, err := ScanSourceFiles(workDir)
	if err == nil || !strings.Contains(err.Error(), "symlink escape") {
		t.Fatalf("Expected symlink escape error from ScanSourceFiles, got: %v", err)
	}
}

func TestAdversarialMidBuildABBASwapIsolatedBySnapshot(t *testing.T) {
	workDir := t.TempDir()
	srcFile := filepath.Join(workDir, "main.go")
	cleanSrc := "package main\nconst Marker = \"CLEAN\"\n"
	if err := os.WriteFile(srcFile, []byte(cleanSrc), 0644); err != nil {
		t.Fatal(err)
	}

	outBin := filepath.Join(workDir, "abba_bin")
	// Script simulates an AB-BA attack on the original workDir mid-build:
	// modifies workDir/main.go to BACKDOOR, copies "./main.go" (from compiler CWD) into outBin, then restores workDir/main.go to CLEAN.
	script := "#!/bin/sh\n" +
		"printf '%s' 'BACKDOOR' > \"" + srcFile + "\"\n" +
		"cp ./main.go \"" + outBin + "\"\n" +
		"printf '%s' '" + strings.ReplaceAll(cleanSrc, "\n", "\\n") + "' > \"" + srcFile + "\"\n"
	// Use exact byte restore via backup file outside scanned extensions
	backup := filepath.Join(t.TempDir(), "orig.bak")
	if err := os.WriteFile(backup, []byte(cleanSrc), 0600); err != nil {
		t.Fatal(err)
	}
	script = "#!/bin/sh\n" +
		"echo 'package main; const Marker = \"BACKDOOR\"' > \"" + srcFile + "\"\n" +
		"cp ./main.go \"" + outBin + "\"\n" +
		"cp \"" + backup + "\" \"" + srcFile + "\"\n"
	scriptPath := filepath.Join(t.TempDir(), "abba_compiler.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	_, err := Wrap(Config{
		Command:      []string{scriptPath},
		WorkDir:      workDir,
		OutputBinary: outBin,
		Hermetic:     true,
	})
	if err != nil {
		t.Fatalf("Wrap failed: %v", err)
	}

	compiled, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compiled), "BACKDOOR") {
		t.Fatalf("Mid-build AB-BA swap succeeded! Staged compiler read BACKDOOR instead of immutable snapshot")
	}
}
