# Repository Guidelines

## Project Structure & Module Organization
This repository is a small Go library module: `github.com/CalypsoSys/joeftp`. The implementation currently lives in [joeftp.go](/home/joe/gocode/joeftp/joeftp.go), which contains the `JoeFtp` client, connection handling, command parsing, and passive-mode transfers. Module metadata is in [go.mod](/home/joe/gocode/joeftp/go.mod). Usage notes and a sample client are in [README.md](/home/joe/gocode/joeftp/README.md).

When adding tests, place them beside the code as `*_test.go` files in the repository root until the package is split into smaller files.

## Build, Test, and Development Commands
Use standard Go tooling:

- `go test ./...` runs the package test suite.
- `env GOCACHE=/tmp/go-build go test ./...` is a useful fallback in restricted environments where the default Go build cache is not writable.
- `gofmt -w joeftp.go` formats the main source file.
- `go test -run TestName ./...` runs a single targeted test while iterating.

There is no separate build step today; validating with `go test` is sufficient for most changes.

## Coding Style & Naming Conventions
Follow idiomatic Go and always format with `gofmt`. Use tabs for indentation as produced by Go tooling. Keep exported API names in `CamelCase` (`LogonAnonymous`, `DeleteFile`) and internal helpers unexported (`sendCommand`, `readCommand`). Prefer small, focused changes because most behavior is concentrated in one file.

Protocol changes should preserve RFC-driven behavior and avoid overly permissive parsing for FTP server responses.

## Testing Guidelines
This repo currently has no committed tests, so new behavior changes should add them where practical. Prefer table-driven tests for command parsing, reply handling, and passive/EPSV edge cases. Name tests with the standard Go pattern, for example `TestReadCommand_MultilineReply` or `TestPassive_EPSVDelimiterValidation`.

## Commit & Pull Request Guidelines
Recent history uses short, plain commit subjects such as `fix all tls...`, `Case insensitivity training`, and `readme`. Keep commits brief, imperative, and scoped to one change.

Pull requests should include a short description, any RFC or server-behavior context, and the exact validation performed (for example `go test ./...`). If a change affects parsing or transfer behavior, include a focused test case or explain why one was not added.
