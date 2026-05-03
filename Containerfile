# syntax=docker/dockerfile:1
# Multi-arch build using buildx TARGETOS/TARGETARCH. Build with:
#   docker buildx build --platform linux/amd64,linux/arm64 -t notrouter:tag .
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags "-s -w \
      -X github.com/scuq/notrouter/internal/version.Version=${VERSION} \
      -X github.com/scuq/notrouter/internal/version.Commit=${COMMIT}" \
    -o /out/notrouter ./cmd/notrouter

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/notrouter /notrouter
USER nonroot:nonroot
EXPOSE 8080 5514/udp 5514/tcp 9090
ENTRYPOINT ["/notrouter"]
CMD ["-config", "/etc/notrouter/config.yaml"]
