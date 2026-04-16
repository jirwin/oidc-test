.PHONY: build test lint clean run docker

BINARY := oidc-test
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) .

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	rm -f *.db *.db-shm *.db-wal

run: build
	./$(BINARY) -port 8080

docker:
	docker build -t oidc-test .
