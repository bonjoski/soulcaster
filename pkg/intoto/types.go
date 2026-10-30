package intoto

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// StatementTypeV1 is the in-toto v1 Statement type URI.
	StatementTypeV1 = "https://in-toto.io/Statement/v1"
	// SLSAPredicateTypeV1 is the SLSA v1.0 Provenance predicate type URI.
	SLSAPredicateTypeV1 = "https://slsa.dev/provenance/v1"
	// SoulcasterBuildTypeV1 is the build type for Soulcaster hermetic compiler builds.
	SoulcasterBuildTypeV1 = "https://bonjoski.github.io/soulcaster/build/v1"
	// SoulcasterBuilderID is the builder identifier.
	SoulcasterBuilderID = "https://github.com/bonjoski/soulcaster"
)

// DigestSet maps cryptographic algorithm names to hexadecimal lowercase digests.
type DigestSet map[string]string

// ResourceDescriptor represents an artifact or input reference.
type ResourceDescriptor struct {
	Name        string            `json:"name,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Digest      DigestSet         `json:"digest"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Content     string            `json:"content,omitempty"`
}

// Statement represents an in-toto v1.0 Statement envelope.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     SLSAProvenanceV1     `json:"predicate"`
}

// SLSAProvenanceV1 represents SLSA v1.0 Provenance predicate.
type SLSAProvenanceV1 struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition holds all parameters and dependencies of the build.
type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   ExternalParameters   `json:"externalParameters"`
	InternalParameters   InternalParameters   `json:"internalParameters"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// ExternalParameters encapsulates user-supplied inputs and commands.
type ExternalParameters struct {
	Command     []string             `json:"command"`
	SourceFiles []ResourceDescriptor `json:"sourceFiles"`
	Environment map[string]string    `json:"environment,omitempty"`
}

// InternalParameters captures compiler toolchain metadata and hermetic flags.
type InternalParameters struct {
	SoulcasterVersion string    `json:"soulcasterVersion"`
	WorkingDir        string    `json:"workingDir"`
	CompilerPath      string    `json:"compilerPath,omitempty"`
	CompilerDigest    DigestSet `json:"compilerDigest,omitempty"`
	HermeticMode      bool      `json:"hermeticMode"`
}

// RunDetails holds execution-specific builder metadata.
type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   BuildMetadata        `json:"metadata"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder describes the entity that executed the build.
type Builder struct {
	ID                  string               `json:"id"`
	Version             map[string]string    `json:"version,omitempty"`
	BuilderDependencies []ResourceDescriptor `json:"builderDependencies,omitempty"`
}

// BuildMetadata captures timing and execution identifier.
type BuildMetadata struct {
	InvocationID string     `json:"invocationId"`
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
}

// NewStatement constructs an in-toto v1.0 Statement with SLSA Provenance v1.
func NewStatement(
	subject []ResourceDescriptor,
	command []string,
	sourceFiles []ResourceDescriptor,
	env map[string]string,
	internal InternalParameters,
	startedOn *time.Time,
	finishedOn *time.Time,
	invocationID string,
	byproducts []ResourceDescriptor,
) *Statement {
	return &Statement{
		Type:          StatementTypeV1,
		Subject:       subject,
		PredicateType: SLSAPredicateTypeV1,
		Predicate: SLSAProvenanceV1{
			BuildDefinition: BuildDefinition{
				BuildType: SoulcasterBuildTypeV1,
				ExternalParameters: ExternalParameters{
					Command:     command,
					SourceFiles: sourceFiles,
					Environment: env,
				},
				InternalParameters: internal,
			},
			RunDetails: RunDetails{
				Builder: Builder{
					ID: SoulcasterBuilderID,
					Version: map[string]string{
						"soulcaster": internal.SoulcasterVersion,
					},
				},
				Metadata: BuildMetadata{
					InvocationID: invocationID,
					StartedOn:    startedOn,
					FinishedOn:   finishedOn,
				},
				Byproducts: byproducts,
			},
		},
	}
}

// ToJSON returns pretty-printed JSON bytes.
func (s *Statement) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// ToJSONL returns single-line JSON bytes terminated with newline.
func (s *Statement) ToJSONL() ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseStatement decodes a JSON payload into a Statement and verifies core envelope fields.
func ParseStatement(data []byte) (*Statement, error) {
	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}
	if err := stmt.Validate(); err != nil {
		return nil, err
	}
	return &stmt, nil
}

// Validate checks standard compliance for in-toto v1 and SLSA v1 schema requirements.
func (s *Statement) Validate() error {
	if s.Type != StatementTypeV1 {
		return fmt.Errorf("invalid _type: expected %q, got %q", StatementTypeV1, s.Type)
	}
	if s.PredicateType != SLSAPredicateTypeV1 {
		return fmt.Errorf("invalid predicateType: expected %q, got %q", SLSAPredicateTypeV1, s.PredicateType)
	}
	if len(s.Subject) == 0 {
		return fmt.Errorf("invalid statement: subject list cannot be empty")
	}
	for i, subj := range s.Subject {
		if subj.Name == "" {
			return fmt.Errorf("subject[%d] name is required", i)
		}
		if len(subj.Digest) == 0 {
			return fmt.Errorf("subject[%d] %q has empty digest set", i, subj.Name)
		}
		if _, ok := subj.Digest["sha256"]; !ok {
			return fmt.Errorf("subject[%d] %q is missing sha256 digest", i, subj.Name)
		}
	}
	if len(s.Predicate.BuildDefinition.ExternalParameters.Command) == 0 {
		return fmt.Errorf("buildDefinition.externalParameters.command cannot be empty")
	}
	return nil
}
