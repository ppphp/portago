.PHONY: build, fmt

all: build

deps:
	GOPROXY=https://goproxy.io go get -u

fmt:
	gofmt -s -w .

build: fmt
	GOPROXY=https://athens.azurefd.net go build
	GOPROXY=https://athens.azurefd.net go build github.com/ppphp/portago/cmd/portageq
	GOPROXY=https://athens.azurefd.net go build github.com/ppphp/portago/cmd/emerge

test:
	go test ./...
