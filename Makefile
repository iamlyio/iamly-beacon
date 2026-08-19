VERSION ?= $(shell tr -d '[:space:]' < VERSION)
LDFLAGS = -s -w -X main.version=v$(VERSION)

.PHONY: build test check format-check module-check run release-snapshot verify-release

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o beacon ./cmd/beacon

test:
	go test ./...

format-check:
	@unformatted="$$(find cmd internal -type f -name '*.go' -print0 | xargs -0 gofmt -l)"; \
		test -z "$$unformatted" || (printf '%s\n' "$$unformatted"; echo "files require gofmt" >&2; exit 1)

module-check:
	go mod verify
	go mod tidy -diff

check: format-check module-check
	go vet ./...
	go test -race ./...

run:
	go run -ldflags "-X main.version=v$(VERSION)" ./cmd/beacon

release-snapshot:
	./scripts/build-release.sh

verify-release:
	./scripts/verify-release.sh
