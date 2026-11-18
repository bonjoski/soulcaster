# ADR-0001: Runtime Hermetic Compiler Provenance & SLSA v1.0 Attestation

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/attest`, `cmd/soulcaster`
- **Deciders:** Lead Supply Chain Architect & Hermetic Build Engineer

---

## 1. Context & Problem Statement

Software supply chain attacks often compromise build pipelines or local developer environments, injecting backdoors into compiled binaries that do not exist in source code (SolarWinds style).
- Traditional code signing signs the final binary, but does not prove *which* commit, compiler flags, or source tree produced it.
- Attestation tools often rely on complex cloud infrastructure (Tekton Chains, cosign cloud keyless services) that cannot operate offline or locally.

---

## 2. Decision Outcome

We built **Soulcaster**, a local hermetic compiler provenance wrapper:

1. **Compiler Interception Wrapper (`soulcaster wrap`):**
   - Intercepts compiler execution, computes SIMD SHA-256 digests of all input source files and compiler binaries.
2. **In-Toto Statement & SLSA v1.0 Generation:**
   - Synthesizes an in-toto predicate linking output binary digest to source git commit tree hash.
3. **Cryptographic Signing via Local Enclave:**
   - Signs attestation predicates using local developer keys or Locksmith Secure Enclave keys (`soulcaster.intoto.jsonl`).
4. **Offline Verification (`soulcaster verify`):**
   - Any consumer can verify binary authenticity offline without external network queries.

---

## 3. Consequences

- **Positive:** Cryptographically guarantees build integrity; achieves SLSA Build L2/L3 locally.
- **Negative:** Adds minimal hashing overhead (< 2%) during full compilation runs.
