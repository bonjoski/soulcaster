# Soulcaster Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, hermetic build provenance models, and SLSA attestation invariants governing [`bonjoski/soulcaster`](https://github.com/bonjoski/soulcaster).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-runtime-hermetic-compiler-provenance-slsa.md)** | **Runtime Hermetic Compiler Provenance & SLSA v1.0 Attestation** | `Accepted` | 2026-10-30 | `pkg/attest`, `cmd/soulcaster` |

---

## Architectural Principles

1. **Lightweight Compiler Wrapper:** Wraps compiler toolchains (`go build`, `cargo build`, `clang`) with `< 2%` build overhead.
2. **In-Toto & SLSA v1.0 Compliance:** Generates signed in-toto statement attestation JSONL files linking source git commit, compiler environment, and output binary SHA-256 digest.
3. **Offline Hermetic Verification:** Enables deterministic offline verification without external internet access or third-party notarization services.
