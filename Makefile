BINARY  := muster
PKG     := ./cmd/muster
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse HEAD 2>/dev/null || echo none)
# The build date is the commit date, so a rebuild of the same commit is byte-identical.
# `format-local:` under TZ=UTC renders the commit instant in UTC; plain `format:` would
# print the committer's own offset behind a false `Z`.
DATE    := $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Defaults for `make fuzz`: 60 seconds in the collectors package, the same
# budget the nightly workflow gives each target.
TIME    ?= 60s
FUZZPKG ?= ./internal/collect/collectors/

.PHONY: build test lint fmt tidy lint-controls coverage refindex refindex-check cisindex cisindex-check suidindex suidindex-check fuzz shellcheck examples-fetch clean

build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test -race ./...

# `gofmt -l` exits 0 whether or not it lists a file, so the target has to
# check for output the way CI does, or a badly formatted tree lints clean.
lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...

lint-controls:
	go run $(PKG) controls lint --references docs/reference
	go run $(PKG) controls lint --references docs/reference --profile default
	go run $(PKG) controls lint --references docs/reference --profile cis-ubuntu2204-l1
	go run $(PKG) controls lint --references docs/reference --profile cis-ubuntu2404-l1
	go run $(PKG) controls lint --references docs/reference --profile cis-rhel9-l1

coverage:
	go run ./tools/coverage

refindex:
	go run ./tools/refindex

refindex-check:
	go run ./tools/refindex -check

cisindex:
	go run ./tools/cisindex

cisindex-check:
	go run ./tools/cisindex -check

# Needs a container runtime and the network; CI runs neither and reads the
# committed docs/reference/suid/*.json instead.
suidindex:
	go run ./tools/suidindex

suidindex-check:
	go run ./tools/suidindex -check

# sh -n and shellcheck over the review scripts (the remedy goldens and the
# committed fix examples) and the round trip's CI scripts (ci/roundtrip: the
# seeds and wait.sh) and the release scripts (scripts/). At least the five
# remedy goldens, the six round-trip scripts and one release script must be
# checked; only the examples glob may match nothing.
shellcheck:
	@n=0; for f in internal/remedy/testdata/*.sh; do sh -n "$$f" || exit 1; shellcheck -s sh "$$f" || exit 1; n=$$((n+1)); done; [ "$$n" -ge 5 ] || { echo "shellcheck: $$n remedy goldens checked, want at least 5"; exit 1; }
	@for f in examples/*-fix-report.sh; do [ -e "$$f" ] || continue; sh -n "$$f" || exit 1; shellcheck -s sh "$$f" || exit 1; done
	@n=0; for f in ci/roundtrip/*.sh; do sh -n "$$f" || exit 1; shellcheck -s sh "$$f" || exit 1; n=$$((n+1)); done; [ "$$n" -ge 6 ] || { echo "shellcheck: $$n roundtrip scripts checked, want at least 6"; exit 1; }
	@n=0; for f in scripts/*.sh; do sh -n "$$f" || exit 1; shellcheck -s sh "$$f" || exit 1; n=$$((n+1)); done; [ "$$n" -ge 1 ] || { echo "shellcheck: $$n release scripts checked, want at least 1"; exit 1; }

# One fuzz target for a short time; the seed corpus already runs in `make
# test`, so this is for the target you are working on. The nightly fuzz
# workflow runs all of them.
fuzz:
	@test -n "$(TARGET)" || { echo "usage: make fuzz TARGET=FuzzParsePasswd [TIME=60s] [FUZZPKG=./internal/pkgfiles/]"; exit 1; }
	go test -run '^$$' -fuzz "^$(TARGET)$$" -fuzztime $(TIME) $(FUZZPKG)

# Downloads the snapshots and reports of an examples.yml run into examples/,
# where a person reviews the diff and commits them (F-12). Needs the gh CLI
# and read access to the repository's Actions artifacts.
examples-fetch:
	@test -n "$(RUN)" || { echo "usage: make examples-fetch RUN=<workflow run id>  (gh run list --workflow examples.yml)"; exit 1; }
	gh run download $(RUN) -n examples-$(RUN) -D examples/

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin
