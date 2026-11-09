package intoto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// DSSEPayloadTypeInToto is the standard DSSE payload media type for in-toto statements.
	DSSEPayloadTypeInToto = "application/vnd.in-toto+json"

	maxKeyFileBytes = 64 << 10 // 64 KiB max key file size
)

// DSSESignature represents a single signature entry inside a DSSE envelope.
type DSSESignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope represents a Dead Simple Signing Envelope (DSSE v1.0).
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// ComputePAE constructs the DSSEv1 Pre-Authentication Encoding byte slice:
// "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
func ComputePAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, len(prefix)+len(payload))
	copy(out, prefix)
	copy(out[len(prefix):], payload)
	return out
}

// KeyIDForPublicKey returns a deterministic SHA-256 hex key identifier for an Ed25519 public key.
func KeyIDForPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// SignStatementDSSE serializes stmt and signs it inside a DSSEv1 Ed25519 envelope,
// returning both the structured envelope and newline-terminated JSONL bytes.
func SignStatementDSSE(stmt *Statement, priv ed25519.PrivateKey) (*DSSEEnvelope, []byte, error) {
	if stmt == nil {
		return nil, nil, errors.New("cannot sign nil statement")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid Ed25519 private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if err := stmt.Validate(); err != nil {
		return nil, nil, fmt.Errorf("statement validation failed before signing: %w", err)
	}

	payloadBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal statement payload: %w", err)
	}

	pae := ComputePAE(DSSEPayloadTypeInToto, payloadBytes)
	sig := ed25519.Sign(priv, pae)
	pub := priv.Public().(ed25519.PublicKey)

	env := &DSSEEnvelope{
		PayloadType: DSSEPayloadTypeInToto,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures: []DSSESignature{
			{
				KeyID: KeyIDForPublicKey(pub),
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal DSSE envelope: %w", err)
	}
	return env, append(envJSON, '\n'), nil
}

// VerifyDSSE verifies a DSSEv1 Ed25519 signed attestation against one or more trusted public keys,
// returning the validated in-toto Statement and the matched key ID.
func VerifyDSSE(data []byte, trustedKeys ...ed25519.PublicKey) (*Statement, string, error) {
	if len(trustedKeys) == 0 {
		return nil, "", errors.New("no trusted Ed25519 public keys provided for DSSE verification")
	}

	var env DSSEEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal DSSE envelope: %w", err)
	}

	if env.PayloadType == "" && len(env.Signatures) == 0 {
		return nil, "", errors.New("unsigned attestation rejected: expected signed DSSE envelope")
	}
	if env.PayloadType != DSSEPayloadTypeInToto {
		return nil, "", fmt.Errorf("unexpected DSSE payloadType %q (want %q)", env.PayloadType, DSSEPayloadTypeInToto)
	}
	if env.Payload == "" {
		return nil, "", errors.New("DSSE envelope payload is empty")
	}
	if len(env.Signatures) == 0 {
		return nil, "", errors.New("DSSE envelope contains zero signatures")
	}

	payloadBytes, err := decodeBase64Flexible(env.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode DSSE base64 payload: %w", err)
	}

	pae := ComputePAE(env.PayloadType, payloadBytes)

	var matchedKeyID string
	verified := false
	for _, entry := range env.Signatures {
		sigBytes, err := decodeBase64Flexible(entry.Sig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		for _, pub := range trustedKeys {
			if len(pub) != ed25519.PublicKeySize {
				continue
			}
			if ed25519.Verify(pub, pae, sigBytes) {
				verified = true
				matchedKeyID = KeyIDForPublicKey(pub)
				break
			}
		}
		if verified {
			break
		}
	}

	if !verified {
		return nil, "", errors.New("DSSE Ed25519 signature verification failed against trusted keys")
	}

	stmt, err := ParseStatement(payloadBytes)
	if err != nil {
		return nil, "", fmt.Errorf("verified DSSE payload failed in-toto statement validation: %w", err)
	}

	return stmt, matchedKeyID, nil
}

// ParseEd25519PrivateKey loads an Ed25519 private key from a file path, PEM block, hex string, or base64 string.
func ParseEd25519PrivateKey(input string) (ed25519.PrivateKey, error) {
	raw, err := resolveKeyMaterial(input)
	if err != nil {
		return nil, err
	}

	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM block for Ed25519 private key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		edPriv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 private key is %T, expected ed25519.PrivateKey", parsed)
		}
		return edPriv, nil
	}

	decoded, err := decodeHexOrBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 private key: %w", err)
	}

	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		priv := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
		if string(priv) != string(decoded) {
			return nil, errors.New("malformed 64-byte Ed25519 private key: public suffix mismatches seed")
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unexpected Ed25519 private key length %d (expected 32-byte seed or 64-byte private key)", len(decoded))
	}
}

// ParseEd25519PublicKey loads an Ed25519 public key from a file path, PEM block, hex string, or base64 string.
func ParseEd25519PublicKey(input string) (ed25519.PublicKey, error) {
	raw, err := resolveKeyMaterial(input)
	if err != nil {
		return nil, err
	}

	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM block for Ed25519 public key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		edPub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PKIX public key is %T, expected ed25519.PublicKey", parsed)
		}
		return edPub, nil
	}

	decoded, err := decodeHexOrBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected Ed25519 public key length %d (expected 32 bytes)", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func resolveKeyMaterial(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", errors.New("empty key material")
	}
	if !strings.Contains(trimmed, "\n") {
		if info, err := os.Stat(trimmed); err == nil && !info.IsDir() {
			f, err := os.Open(trimmed)
			if err != nil {
				return "", fmt.Errorf("failed to open key file %q: %w", trimmed, err)
			}
			defer f.Close()
			buf, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
			if err != nil {
				return "", fmt.Errorf("failed to read key file %q: %w", trimmed, err)
			}
			if len(buf) > maxKeyFileBytes {
				return "", fmt.Errorf("key file %q exceeds %d bytes", trimmed, maxKeyFileBytes)
			}
			return strings.TrimSpace(string(buf)), nil
		}
	}
	return trimmed, nil
}

func decodeHexOrBase64(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return decodeBase64Flexible(s)
}

func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
