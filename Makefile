# Developer entry points. CI runs the same commands (.github/workflows/go-ci.yml).
COMPOSE := docker compose -f deploy/dev/docker-compose.yml

.PHONY: build vet test test-integration fmt-check dev-up dev-down run tenant-exempt

build:
	go build ./...

vet:
	go vet ./...

# Unit tests. DB-backed unit tests skip when no Postgres is listening on :5432.
test:
	go test ./...

# Integration suites (testcontainers Postgres; Docker required). -p 1 because
# parallel packages race on the testcontainers reaper.
test-integration:
	go test -tags integration -p 1 ./tests/integration/flows/ ./tests/integration/onboarding/ ./tests/integration/flagsoff/ -count=1

# Lists files changed against origin/main that gofmt would rewrite.
fmt-check:
	@git diff --name-only --diff-filter=AM origin/main -- '*.go' | xargs -r gofmt -l

# Every raw query outside the tenant-scoped layer must say why (ADR-0001 §4.3).
tenant-exempt:
	@scripts/check-tenant-exempt.sh

dev-up:
	$(COMPOSE) up -d --wait postgres hydra vault
	$(COMPOSE) up vault-init

dev-down:
	$(COMPOSE) down

run:
	set -a && . deploy/dev/dev.env && set +a && go run ./cmd
