# Contributing to oidc-test

## Development Setup

```sh
git clone https://github.com/jirwin/oidc-test.git
cd oidc-test
make build
./oidc-test
```

## Running Tests

```sh
make test
```

## Linting

```sh
make lint
```

Requires [golangci-lint](https://golangci-lint.run/welcome/install/).

## Pull Requests

- Include tests for new features
- Ensure `make lint` and `make test` pass
- Keep changes focused - one feature or fix per PR
