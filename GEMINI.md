# Newplex Context


## Project Overview
Newplex is a high-performance, incremental, stateful cryptographic primitive (Duplex) and high-level Protocol implemented in Go. It uses the Simpira-1024 permutation.

**Critical Resources:**
- `design.md`: The authoritative source for the cryptographic construction, protocol logic, and security claims. ALWAYS check this before modifying core logic.
- `internal/simpira1024`: Contains the core permutation logic, including optimized assembly (`.s`) for AMD64/ARM64 and a generic Go implementation.

## Development Guidelines

## 0. Specific Instructions For AI Agents

- DO NOT ATTEMPT TO DOWNGRADE THE VERSION OF ANYTHING.
- DO NOT AUTOMATICALLY COMMIT YOUR CHANGES.

### 1. Testing & Verification
This project uses standard Go testing, fuzzing, and benchmarking.

- **Test Packages:** Use `package name_test` whenever possible to ensure we are testing the public API.
- **Internal Testing:** For critical internal functionality (like the `duplex` type), tests should be placed in the same package. In these cases, disable the `testpackage` lint for that file with an explanatory comment.
- **Run all tests:**
  ```bash
  go test ./...
  ```
- **Run with race detector:**
  ```bash
  go test -race ./...
  ```
- **Run Linter:**
  ```bash
  golangci-lint run ./...
  ```

### 2. Fuzzing
Fuzz tests are located in `fuzz_constructions_test.go` and `fuzz_transcripts_test.go`. When modifying `duplex.go` or `protocol.go`, run relevant fuzzers to ensure stability.
```bash
go test -fuzz=FuzzConstructions -fuzztime=10s
go test -fuzz=FuzzTranscripts -fuzztime=10s
```

### 3. Benchmarking
Performance is a key feature (10+ Gb/s). Always verify performance impacts when touching core paths. Before beginning to
optimize, record a set of benchmark measurements in a text file:
```bash
GOMAXPROCS=1 go test -bench=BenchmarkBeingOptimizedFor -benchtime=3s -benchmem -count=10 | tee baseline.txt
```
Once you've recorded a baseline measurement set, apply your changes to optimize the code. Next, record a set of
benchmark measurements of the optimized code in a separate text file (e.g., `optimized.txt`). Finally, use `benchstat`
to compare the two sets of measurements to see if the result is statistically significant:
```bash
benchstat baseline.txt optimized.txt
```
If `benchstat` is not available, feel free to install it:
```bash
go install golang.org/x/perf/cmd/benchstat@latest
```

### 4. Cross-Platform / Pure Go
The project has optimized assembly and a fallback Go implementation.
- **Test the "pure Go" fallback:**
  ```bash
  go test -tags purego ./...
  ```
- **Assembly Files:** Be extremely cautious editing `simpira_amd64.s` or `simpira_arm64.s`.

### 5. Security & Safety (CRITICAL)
- **Constant Time:** Use `crypto/subtle` for all comparisons of secrets/tags.
- **Zeroing Memory:** Secrets should be wiped from memory when no longer needed (e.g., `clear(buf)`).
- **In-Place Operations:** `Open` performs in-place decryption. Ensure error paths handle potentially corrupted plaintext correctly (the current implementation zeroes it out).
- **No Secret Logging:** Never log key material, plaintexts, or internal state.

## Code Style
- Follow standard Go conventions.
- Use `internal/` packages to hide implementation details (`simpira1024`, `tuplehash`).
- Comments should explain *why* (cryptographic rationale), not just *what*.

## Common Linter Warnings
- `testpackage`: Preferred whenever possible. For unit tests of critical internals, same-package tests are permitted if the lint is disabled in-file with a comment explaining why.
- `gosec`: Should be mitigated wherever possible. If the warning is a false positive, the lint should be disabled for that statement with an explanatory comment explaining WHY it is a false positive.

## Assembly Files (`*.s`)
- Any `.s` file which does not end in a newline will produce an "unexpected EOF" error on compilation. If you forget to
  add a newline when writing a `.s` file, you can use `echo '' >> file.s` to quickly append a newline.