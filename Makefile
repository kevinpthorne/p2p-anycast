.PHONY: all build test clean proto vendor

all: build test

build:
	go build -v ./cmd/...

test:
	go test -v -race ./...

proto:
	buf generate proto

vendor:
	go mod tidy && go mod vendor

clean:
	rm -rf bin/
