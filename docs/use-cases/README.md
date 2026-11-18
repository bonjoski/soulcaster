# 💡 Soulcaster End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/soulcaster`](https://github.com/bonjoski/soulcaster)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Soulcaster** is an ultra-low-overhead runtime compiler wrapper and SLSA Level 3 supply-chain provenance generator. It enforces hermeticity during build time, neutralizes host environment variable leakage, and outputs cryptographically signed in-toto attestations on developer workstations and CI runners without requiring heavyweight build tools like Bazel.

This directory provides task-oriented recipes for reproducible builds and supply-chain verification.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Standard |
| :--- | :--- | :--- | :--- |
| **[01. Hermetic Compiler Wrapping](01-hermetic-compiler-wrapping.md)** | Wrap Go/Rust/C compilers to enforce deterministic outputs, strip ambient host paths, and normalize timestamps. | `soulcaster wrap -- go build ...` | Hermetic Build Boundary |
| **[02. SLSA Level 3 Provenance Attestation](02-slsa-provenance-attestation.md)** | Generate cryptographically signed in-toto and SLSA v1.0 provenance files during release builds. | `soulcaster wrap --attest -- <cmd>` | SLSA v1.0 / in-toto |
| **[03. Offline Provenance Verification](03-offline-provenance-verification.md)** | Verify that a release binary matches its cryptographic provenance and was built from clean git state. | `soulcaster verify <binary> <pred>` | Cryptographic Verification |
