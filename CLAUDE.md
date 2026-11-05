# Claude Code Guidelines for `soulcaster`


## Build & Test Commands
- **Build Binary:** `go build -o bin/soulcaster ./cmd/soulcaster`
- **Unit Tests:** `go test -v ./...`
- **Linter:** `golangci-lint run`
- **Wrap Compiler:** `./bin/soulcaster wrap -o <out> -- <compiler-cmd>`
- **Verify Attestation:** `./bin/soulcaster verify --binary <out> --attestation <out>.intoto.jsonl`

## Code Style & Architectural Invariants
- Pre/post source tree SHA-256 snapshotting: abort and shred binary if files change mid-build.
- Strict network hermeticity: `GOPROXY=off`, `GOSUMDB=off`.
- in-toto v1.0 Statement & SLSA v1.0 Provenance predicate compliance.
- Strips timestamps and absolute paths from build artifacts (`-trimpath`).

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
