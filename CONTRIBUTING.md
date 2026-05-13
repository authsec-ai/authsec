# Contributing to AuthSec

Thank you for your interest in contributing to AuthSec! This guide explains how to get started.

## Development Setup

1. **Prerequisites**: Go 1.25+, PostgreSQL 15+
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

## Architecture

authsec is a **single-tenant** authentication service. Multi-tenant functionality is handled by the separate **mt-plugin** gRPC microservice. When `MT_PLUGIN_GRPC_ADDR` is set, authsec connects to mt-plugin and multi-tenant registration is enabled. Without it, only one admin is allowed (HTTP 409 on second registration).

## Code Style

- Run `go vet ./...` before committing.
- Run `golangci-lint run` if installed (see `.golangci.yml` for enabled linters).
- Follow standard Go conventions: <https://go.dev/doc/effective_go>.
- Keep functions short and focused. Prefer returning errors over panicking.
- No comments unless the WHY is non-obvious. Never comment what the code does.
- All controllers use `config.DB` (master DB) directly — no dynamic tenant DB switching.

## Testing

All test files live in `tests/unit/` and `tests/integration/`. Production packages contain no test files.

```bash
# Unit tests — no DB required, fast
go test -short ./tests/unit/

# Unit tests with race detector
go test -short -race ./tests/unit/

# Integration tests — requires a running PostgreSQL instance
RUN_INTEGRATION=1 go test ./tests/unit/ ./tests/integration/...
```

**In CI (GitHub Actions):**
- Unit tests run automatically on every PR.
- Integration tests run when the PR has the `run-integration` label — a Postgres container is spun up automatically.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes in focused, well-described commits.
3. Ensure all unit tests pass and `go vet` is clean.
4. Open a PR against `main` with a clear description of the change.
5. Add the `run-integration` label if your change touches DB logic, migrations, or auth flows.
6. At least one maintainer approval is required before merging.

## Reporting Issues

Use GitHub Issues. Include:
- Steps to reproduce
- Expected vs. actual behaviour
- Go version, OS, and relevant environment details

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
