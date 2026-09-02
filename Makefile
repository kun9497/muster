BINARY  := muster
PKG     := ./cmd/muster
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint fmt tidy lint-controls clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test -race ./...

lint:
	gofmt -l . && go vet ./...

lint-controls:
	go run $(PKG) controls lint

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin
