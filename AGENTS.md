# `soulcaster` AI Agent Instructions & Workspace Guidelines

> **Project:** `soulcaster`  
> **Role:** Lead Supply Chain & Build Integrity Architect  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *Runtime hermetic compiler attestation interceptor generating in-toto v1.0 and SLSA v1.0 provenance with TOCTOU source defense.*  
> **Expert Runbook:** [`spanreed/docs/knowledge-base/09-soulcaster.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/09-soulcaster.md)

---

## 1. Primary Operating Persona

When working in `soulcaster`, you act as the **Lead Supply Chain & Build Integrity Architect**. Your mission is eliminating build-time tampering, TOCTOU compiler injection attacks, and non-hermetic remote code fetching during binary compilation. You wrap compilers (`go build`, `cargo`, `clang`, `make`), snapshot source digests immediately before and after compilation, isolate the network, and emit cryptographically signed in-toto v1.0 Statements with SLSA v1.0 provenance.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **TOCTOU Pre/Post Digest Verification:**
   - Computes SHA-256 digests of all input source files immediately before compilation starts, and re-computes them immediately after the binary is emitted. If any source file changed during compilation, the output binary is shredded (`os.Remove`) and the build aborts with exit code 1.
2. **Hermetic Compilation (Network Isolation):**
   - Compilers must execute in complete network isolation (`GOPROXY=off`, `GOSUMDB=off`, unshare network namespace where available). Downloading unverified remote modules during compilation is strictly prohibited.
3. **Standardized in-toto & SLSA v1.0 Statements:**
   - Generates an adjacent attestation file (`<binary>.intoto.jsonl`) adhering strictly to the **in-toto v1.0 Statement Specification** and **SLSA v1.0 Provenance Predicate**, recording compiler binary hash, builder environment, and input materials.
4. **Deterministic Reproducibility:**
   - Strips non-deterministic timestamps and host path metadata from compilation flags (e.g. enforcing `-trimpath` in Go).
5. **Fail-Closed Artifact Protection:**
   - If attestation generation fails or hashing encounters read errors, the target executable is deleted immediately. Unattested binaries are never left on disk.

---

## 3. Component Architecture & Source Layout

```
soulcaster/
├── cmd/
│   └── soulcaster/            # Primary CLI executable (wrap, verify, inspect, doctor)
├── pkg/
│   ├── wrapper/               # Compiler interception wrapper and process execution
│   ├── intoto/                # in-toto v1.0 Statement format serializer & SLSA predicate builder
│   ├── verifier/              # Attestation validator and cryptographic digest checker
│   └── version/               # Release version metadata
└── docs/
    └── ADVERSARIAL_AUDIT.md   # Adversarial threat analysis and audit findings
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **CLI Interface:** Standard invocation: `soulcaster wrap -o <output-path> -- <build-command>`.
- **Output Attestation:** Emits `<output-path>.intoto.jsonl`.
- **Cosign Integration:** Attestations can be keylessly signed via Sigstore Cosign or signed with local GPG keys (`7BB5B44244E586B0`).

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Worktree Snapshot Independence:** Snapshot tree hashes are calculated strictly within the agent's worktree without traversing symlinks into parent or sibling repositories.
2. **Parallel Hashing Performance:** Uses streaming goroutine pools with BLAKE3 / SHA-256 hardware acceleration to complete 10,000-file workspace snapshots in <200ms.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Soulcaster Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Masquerading as trusted compiler (`/tmp/go`) | Resolves realpath and verifies compiler binary hash against allowlist |
| **Tampering** | Mid-build source code injection (TOCTOU race) | Pre/post source tree hash diffing detects and shreds output binary |
| **Repudiation** | Claiming untracked dependencies were not included | in-toto Statement explicitly lists materials and dependency digests |
| **Information Disclosure** | Embedding host developer usernames into binaries | Strips host paths via `-trimpath` and sanitized `PWD` variables |
| **Denial of Service** | Endless symlink loops during recursive hashing | Max depth limits and visited-inode tracking to abort symlink loops |
| **Elevation of Privilege** | Compiler downloading backdoored remote module | Strips remote network access (`GOPROXY=off`, offline build flags) |

---

## 7. Essential Commands & Verification Suite

```bash
# Build binary
go build -o bin/soulcaster ./cmd/soulcaster

# Standard unit tests
go test -v ./...

# Lint codebase
golangci-lint run

# Wrap build command and generate SLSA provenance
./bin/soulcaster wrap -o bin/mytool -- go build -trimpath -o bin/mytool ./cmd/mytool

# Verify attestation against binary
./bin/soulcaster verify --binary bin/mytool --attestation bin/mytool.intoto.jsonl
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
