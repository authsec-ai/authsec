# Contributing to AuthSec

Thank you for your interest in contributing to AuthSec! This guide explains how to get started.

## Development Setup

1. **Prerequisites**: Go 1.25+, PostgreSQL 15+, Redis 7+
2. Clone the repository:
   ```bash
   git clone https://github.com/authsec-ai/authsec.git
   cd authsec
   ```
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Copy and configure environment variables (see `README.md` for the full list).
5. Run the service:
   ```bash
   go run ./cmd/main.go
   ```

## Code Style

- Run `go vet ./...` before committing.
- Run `golangci-lint run` if installed (see `.golangci.yml`).
- Follow standard Go conventions: <https://go.dev/doc/effective_go>.
- Keep functions short and focused. Prefer returning errors over panicking.

## Runtime QA

Use the manual API checklist in [`docs/runtime-qa-curls.md`](docs/runtime-qa-curls.md).
It is the supported verification path for this repository and is intended to be
imported into Postman or run directly with `curl`.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes in focused, well-described commits.
3. Ensure `go build ./...` succeeds, the runtime curl checklist is covered, and `go vet` is clean.
4. Open a PR against `main` with a clear description of the change.
5. At least one maintainer approval is required before merging.

## Reporting Issues

Use GitHub Issues. Include:
- Steps to reproduce
- Expected vs. actual behaviour
- Go version, OS, and relevant environment details

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
