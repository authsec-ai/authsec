# AuthSec agent runtime gateway (SPEC-agent-runtime-gateway.md).
# Build from the repository root:
#   docker build -f deploy/agent-gateway/Dockerfile -t authsec/agent-gateway:dev .
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
RUN apk add --no-cache ca-certificates && update-ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY internal/agentgateway ./internal/agentgateway
COPY internal/igagov ./internal/igagov
COPY cmd/agent-gateway ./cmd/agent-gateway
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X github.com/authsec-ai/authsec/internal/agentgateway/gateway.Version=${VERSION}" \
      -o /out/agent-gateway ./cmd/agent-gateway

# One static binary, CA certificates, no shell, non-root.
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/agent-gateway /agent-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/agent-gateway"]
CMD ["-config", "/etc/agent-gateway/config.yaml"]
