BINARY  := muster
PKG     := ./cmd/muster
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint fmt tidy lint-controls coverage refindex refindex-check clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test -race ./...

# `gofmt -l` exits 0 whether or not it lists a file, so the target has to
# check for output the way CI does, or a badly formatted tree lints clean.
lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...

lint-controls:
	go run $(PKG) controls lint --references docs/reference

coverage:
	go run ./tools/coverage

refindex:
	go run ./tools/refindex

refindex-check:
	go run ./tools/refindex -check

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin
