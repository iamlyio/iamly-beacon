VERSION ?= $(shell tr -d '[:space:]' < VERSION)
LDFLAGS = -s -w -X main.version=v$(VERSION)

.PHONY: build development-build test check format-check module-check installer-test run release-snapshot verify-release

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o beacon ./cmd/beacon

development-build:
	go build -tags development -trimpath -ldflags "-s -w -X main.version=v$(VERSION)-development" -o beacon-development ./cmd/beacon

test:
	go test ./...

format-check:
	@unformatted="$$(find cmd internal -type f -name '*.go' -print0 | xargs -0 gofmt -l)"; \
		test -z "$$unformatted" || (printf '%s\n' "$$unformatted"; echo "files require gofmt" >&2; exit 1)

module-check:
	go mod verify
	go mod tidy -diff

installer-test:
	./scripts/test-install.sh

check: format-check module-check installer-test
	go vet ./...
	go test -race ./...

run:
	go run -ldflags "-X main.version=v$(VERSION)" ./cmd/beacon

release-snapshot:
	./scripts/build-release.sh

verify-release:
	./scripts/verify-release.sh
