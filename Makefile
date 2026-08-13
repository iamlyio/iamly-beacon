.PHONY: build test check run

build:
	go build -trimpath -ldflags "-s -w" -o beacon ./cmd/beacon

test:
	go test ./...

check:
	go vet ./...
	go test -race ./...

run:
	go run ./cmd/beacon
