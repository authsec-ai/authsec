FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates && update-ca-certificates

ENV APPHOME=/app
WORKDIR $APPHOME

ENV GIT_TERMINAL_PROMPT=0

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify

COPY . ./

# Honor buildkit TARGETARCH so the same Dockerfile produces amd64 or arm64 binaries.
ARG TARGETARCH
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}
ENV CGO_ENABLED=0

# Build identity, injected at link time and served at
# /authsec/uflow/version.
#
# Without these the endpoint reports "unknown", which is correct for a local
# `go build` and useless for a deployed image -- so every build that produces
# something deployable must pass them. The CI workflow does; a hand-run
# `docker build` that forgets will announce itself as unknown rather than
# quietly claiming to be some commit.
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILT_AT=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build \
      -ldflags "-s -w \
        -X github.com/authsec-ai/authsec/internal/buildinfo.Commit=${GIT_COMMIT} \
        -X github.com/authsec-ai/authsec/internal/buildinfo.Branch=${GIT_BRANCH} \
        -X github.com/authsec-ai/authsec/internal/buildinfo.BuiltAt=${BUILT_AT}" \
      -o /main ./cmd/main.go

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl && update-ca-certificates

RUN addgroup -g 1000 appgroup \
 && adduser -D -u 1000 -G appgroup appuser

ENV APPHOME=/app
WORKDIR $APPHOME

COPY --from=builder /main ./
COPY --from=builder /app/migrations ./migrations

RUN chown -R 1000:1000 $APPHOME \
 && chmod +x ./main

USER 1000

EXPOSE 7468

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:7468/authsec/uflow/health || exit 1

CMD ["./main"]
