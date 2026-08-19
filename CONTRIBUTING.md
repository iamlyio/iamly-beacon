# Contributing to iamly Beacon

Thank you for helping improve Beacon. Changes should preserve its narrow trust
boundary, least-privilege defaults, and explicit failure behavior.

## Before opening a change

- Use a public issue for bugs and feature proposals that contain no sensitive
  information.
- Use [private vulnerability reporting](SECURITY.md) for security concerns.
- Keep collector permissions read-only and request only the fields required for
  access review evidence.
- Never add real tokens, credentials, customer data, private keys, or captured
  vendor responses to tests or documentation.

## Development

Beacon requires the Go version declared in `go.mod`.

```sh
git clone https://github.com/iamlyio/iamly-beacon.git
cd iamly-beacon
make check
make build
./beacon version
```

Before submitting a pull request:

```sh
find cmd internal -type f -name '*.go' -exec gofmt -w {} +
go mod tidy
make check
```

Add focused tests for behavioral changes. Tests should use synthetic values and
local HTTP servers; they must not call live vendor APIs.

## Pull requests

Explain the problem, the security and privacy impact, the verification you ran,
and any operator-facing changes. Keep changes focused. By contributing, you
agree that your contribution is licensed under the Apache License 2.0.
