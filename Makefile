VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS  = -s -w \
           -X github.com/scuq/notrouter/internal/version.Version=$(VERSION) \
           -X github.com/scuq/notrouter/internal/version.Commit=$(COMMIT)

.PHONY: build run test vet tidy clean docker

build:
	go build -ldflags "$(LDFLAGS)" -o bin/notrouter ./cmd/notrouter

run:
	go run ./cmd/notrouter

test:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t notrouter:$(VERSION) .
