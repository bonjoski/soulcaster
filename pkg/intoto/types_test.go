package intoto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInTotoStatementGenerationSchema(t *testing.T) {
	now := time.Now().UTC()
	finish := now.Add(2 * time.Second)

	subjects := []ResourceDescriptor{
		{
			Name: "mybinary",
			Digest: DigestSet{
				"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
	}
	command := []string{"go", "build", "-o", "mybinary", "./..."}
	sources := []ResourceDescriptor{
		{
			Name: "main.go",
			URI:  "file://main.go",
			Digest: DigestSet{
				"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			},
		},
	}
	env := map[string]string{
		"GOOS":   "darwin",
		"GOARCH": "arm64",
	}
	internal := InternalParameters{
		SoulcasterVersion: "0.1.0",
		WorkingDir:        "/tmp/build",
		CompilerPath:      "/usr/local/go/bin/go",
		CompilerDigest: DigestSet{
			"sha256": "1111111111111111111111111111111111111111111111111111111111111111",
		},
		HermeticMode: true,
	}
	byproducts := []ResourceDescriptor{
		{
			Name: "networkMonitor",
			Annotations: map[string]string{
				"externalSocketsOpened": "0",
				"hermetic":               "true",
			},
		},
	}

	stmt := NewStatement(
		subjects,
		command,
		sources,
		env,
		internal,
		&now,
		&finish,
		"inv-12345",
		byproducts,
	)

	// Validate statement struct
	if err := stmt.Validate(); err != nil {
		t.Fatalf("Statement validation failed: %v", err)
	}

	// Verify JSON output
	data, err := stmt.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Unmarshal to generic map to verify JSON keys match in-toto / SLSA spec
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if raw["_type"] != "https://in-toto.io/Statement/v1" {
		t.Errorf("Unexpected _type: %v", raw["_type"])
	}
	if raw["predicateType"] != "https://slsa.dev/provenance/v1" {
		t.Errorf("Unexpected predicateType: %v", raw["predicateType"])
	}

	// Verify JSONL output
	jsonlData, err := stmt.ToJSONL()
	if err != nil {
		t.Fatalf("ToJSONL failed: %v", err)
	}
	if !strings.HasSuffix(string(jsonlData), "\n") {
		t.Errorf("JSONL output must end with newline")
	}

	// Test ParseStatement roundtrip
	parsed, err := ParseStatement(jsonlData)
	if err != nil {
		t.Fatalf("ParseStatement failed: %v", err)
	}
	if parsed.Subject[0].Name != "mybinary" {
		t.Errorf("Expected subject name 'mybinary', got %q", parsed.Subject[0].Name)
	}
	if parsed.Subject[0].Digest["sha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Mismatch in subject sha256: %s", parsed.Subject[0].Digest["sha256"])
	}
	if len(parsed.Predicate.BuildDefinition.ExternalParameters.SourceFiles) != 1 {
		t.Fatalf("Expected 1 source file, got %d", len(parsed.Predicate.BuildDefinition.ExternalParameters.SourceFiles))
	}
}

func TestStatementValidationFailures(t *testing.T) {
	// Missing subject
	stmt := &Statement{
		Type:          StatementTypeV1,
		PredicateType: SLSAPredicateTypeV1,
		Subject:       []ResourceDescriptor{},
	}
	if err := stmt.Validate(); err == nil {
		t.Errorf("Expected error for empty subjects, got nil")
	}

	// Invalid type
	stmt = &Statement{
		Type:          "https://invalid.type",
		PredicateType: SLSAPredicateTypeV1,
		Subject: []ResourceDescriptor{
			{Name: "bin", Digest: DigestSet{"sha256": "abc"}},
		},
	}
	if err := stmt.Validate(); err == nil {
		t.Errorf("Expected error for invalid _type, got nil")
	}

	// Missing sha256 in subject
	stmt = &Statement{
		Type:          StatementTypeV1,
		PredicateType: SLSAPredicateTypeV1,
		Subject: []ResourceDescriptor{
			{Name: "bin", Digest: DigestSet{"md5": "abc"}},
		},
	}
	if err := stmt.Validate(); err == nil {
		t.Errorf("Expected error for missing sha256 in subject digest, got nil")
	}
}
