- Run tests before and after modifying the code to ensure correctness:
  ```bash
  go test ./...
  ```

- Run code linters after modifying the code to ensure consistency and to catch bugs:
  ```bash
  golangci-lint run ./...
  ```
  
  Some linter warnings can be automatically fixed:
  ```bash
  golangci-lint run ./... --fix
  ```
  
  If a linter warning cannot be automatically fixed, either ask for help or check to see if it is a false positive.
  Common false positives include:
  
  - `testpackage` warnings for tests which are necessarily testing package internals. Disable these by adding
    a `//nolint:testpackage // an explanation of why this is necessary` comment at the end of the package declaration
    line.
  - `gosec` warnings for integer overflows which are not possible. Disable these by adding a
    `//nolint:gosec // an explanation of why this is a false positive` comment at the end of the line.

- Format the code after modifying it:
  ```bash
  golangci-lint fmt ./...
  ```

- When writing tests, prefer the use of data-driven tests with anonymous structs to long, sequential tests.
  Ensure the anonymous struct includes a `name` field and that each test is run in a `t.Run` closure to provide
  separation.

- When writing tests, prefer the use of nested `t.Run` closures to additional `func TestType_Method_Case` functions.

- When writing tests, use a got/want structure for assertions:
  ```go
  if got, want := calculatedValue, "fixture"; got != want {
    t.Errorf("Method(%v) = %v, want = %v", input, got, want)
  }
  ```

- When writing tests, add clarifying comments about what is being tested and why.

- When optimizing code, run benchmarks before and after changing the code. Use `-benchtime=5s` to ensure a stable
  measurement. If possible, use `-count=10` and record the output to a text file to capture multiple measurements, then
  use `benchstat` to compare the before and after text files. Do not accept optimizations which do not provide
  statistically significant improvements in latency, throughput, or memory usage.