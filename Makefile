VERSION ?= $(shell tr -d '[:space:]' < VERSION)
LDFLAGS = -s -w -X main.version=v$(VERSION)

.PHONY: build test check run

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o beacon ./cmd/beacon

test:
	go test ./...

check:
	go vet ./...
	go test -race ./...

run:
	go run -ldflags "-X main.version=v$(VERSION)" ./cmd/beacon
