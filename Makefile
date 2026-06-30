VERSION := $(shell cat VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := nft-okboy
DIST    := nft-okboy
GO      ?= go

.PHONY: build static release-bins test vet fmt integration release clean

# Host build (dev).
build:
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/nft-okboy

# Single static linux/amd64 binary. CGO_ENABLED=0 forces the pure-Go
# modernc.org/sqlite driver → no libc dependency, drops onto any Linux host.
static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-amd64 ./cmd/nft-okboy

# All release architectures. Because the project is pure Go (CGO_ENABLED=0 + the
# pure-Go modernc.org/sqlite driver), cross-compiling is free — no C toolchain.
release-bins:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64       $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-amd64 ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=386         $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-386 ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64       $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-arm64 ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-armv7 ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-armv6 ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64     $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-riscv64 ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=ppc64le     $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-ppc64le ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=s390x       $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-s390x ./cmd/nft-okboy
	CGO_ENABLED=0 GOOS=linux GOARCH=loong64     $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(DIST)-linux-loong64 ./cmd/nft-okboy
	cd dist && sha256sum $(DIST)-linux-* > SHA256SUMS

# Hermetic unit tests (run anywhere, incl. non-Linux dev — MockBackend, no nft/root).
test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# Real-nftables integration test (Linux + root). Runs in an isolated network
# namespace so it never touches the host / k8s firewall.
integration:
	$(GO) test -tags integration -c -o /tmp/nft-okboy-nfttest ./internal/firewall/
	sudo ip netns add okboy_it_ns 2>/dev/null || true
	sudo ip netns exec okboy_it_ns env PATH=/usr/sbin:/usr/bin:/bin /tmp/nft-okboy-nfttest -test.run TestNftIntegration -test.v; \
		rc=$$?; sudo ip netns del okboy_it_ns 2>/dev/null || true; exit $$rc

# Release tarball: static binary + deploy assets + config example.
release: static
	tar -czf dist/$(DIST)-$(VERSION)-linux-amd64.tar.gz \
		-C dist $(DIST)-linux-amd64 \
		-C .. config.example.yaml deploy

clean:
	rm -rf bin dist
