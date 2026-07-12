# syntax=docker/dockerfile:1.7
#
# Isolated high-interaction decoy responder. Runs as its own container,
# deliberately holding no credentials and reaching no production system:
# it can only ever answer with canned data and report the engagement.
# Build from the repo root:
#   docker build -f cmd/decoy-responder/Dockerfile -t intentgate-decoy-responder .

# ---- build stage ------------------------------------------------------------
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=0 GOOS=linux
ARG VERSION=dev
RUN go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/decoy-responder \
      ./cmd/decoy-responder

# ---- runtime stage ----------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.title="intentgate-decoy-responder"
LABEL org.opencontainers.image.description="Isolated high-interaction decoy for the IntentGate deception fabric"
LABEL org.opencontainers.image.source="https://github.com/IntentGate-app/intentgate-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="IntentGate-app"

WORKDIR /
COPY --from=build /out/decoy-responder /decoy-responder

EXPOSE 8090
ENTRYPOINT ["/decoy-responder"]
