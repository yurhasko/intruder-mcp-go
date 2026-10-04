# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.27.1
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" -o /out/intruder-mcp ./cmd/intruder-mcp

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/intruder-mcp /usr/local/bin/intruder-mcp
COPY LICENSE.md THIRD_PARTY_LICENSES.md /usr/share/licenses/intruder-mcp/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/intruder-mcp"]
