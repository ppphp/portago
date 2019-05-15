.PHONY: build, fmt

all: build

deps:
	GOPROXY=https://goproxy.io go get -u

fmt:
	gofmt -s -w .

build: fmt
	GOPROXY=https://goproxy.io go build
	GOPROXY=https://goproxy.io go build github.com/ppphp/portago/cmd/portageq
	GOPROXY=https://goproxy.io go build github.com/ppphp/portago/cmd/emerge

test:
	go test ./...
