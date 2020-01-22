.PHONY: build, fmt

all: build

portageq: fmt
	GOPROXY=https://goproxy.io go build ./cmd/portageq

emerge: fmt
	GOPROXY=https://goproxy.io go build ./cmd/emerge

deps:
	GOPROXY=https://goproxy.io go get -u

fmt:
	goimports -w .

build:
	GOPROXY=https://goproxy.io go build
	GOPROXY=https://goproxy.io go build ./cmd/emerge

test:
	go test ./...
