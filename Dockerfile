FROM golang:1.24-alpine AS build
WORKDIR /src

ARG VERSION=dev
ARG COMMIT=unknown

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X github.com/scuq/notrouter/internal/version.Version=${VERSION} -X github.com/scuq/notrouter/internal/version.Commit=${COMMIT}" \
    -o /out/notrouter ./cmd/notrouter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/notrouter /usr/local/bin/notrouter
COPY config.yaml /etc/notrouter/config.yaml
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/notrouter"]
CMD ["-config=/etc/notrouter/config.yaml"]
