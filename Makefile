.PHONY: build, fmt

all: build

portageq: fmt
	GOPROXY=https://goproxy.io go build github.com/ppphp/portago/cmd/portageq

deps:
	GOPROXY=https://goproxy.io go get -u

fmt:
	gofmt -s -w .

build:
	GOPROXY=https://goproxy.io go build
	GOPROXY=https://goproxy.io go build github.com/ppphp/portago/cmd/emerge

test:
	go test ./...
