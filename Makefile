.PHONY: build, fmt

all: build

GOPROXY=https://goproxy.cn

portageq: fmt
	go build ./cmd/portageq

emerge: fmt
	go build ./cmd/emerge

deps:
	go get -u

fmt:
	goimports -w .

build:
	go build ./cmd/emerge

test:
	go test ./...
