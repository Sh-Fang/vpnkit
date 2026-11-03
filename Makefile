GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
export CGO_ENABLED := 0

.PHONY: build test lint dist clean testserver

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/vpnkit ./cmd/vpnkit

testserver:
	$(GO) build -trimpath -o bin/testserver ./cmd/testserver

# -race 需要 cgo
test:
	CGO_ENABLED=1 $(GO) test ./... -race -count=1

lint:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

dist:
	@mkdir -p dist
	@for os in darwin linux windows; do for arch in amd64 arm64; do \
	  ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	  echo "build $$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "dist/vpnkit-$$os-$$arch$$ext" ./cmd/vpnkit || exit 1; \
	done; done
	cd dist && sha256sum vpnkit-* > SHA256SUMS

clean:
	$(GO) clean
	rm -f bin/vpnkit bin/testserver dist/vpnkit-* dist/SHA256SUMS
