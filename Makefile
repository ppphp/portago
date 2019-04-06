.PHONY: build, fmt

all: build

fmt:
	gofmt -s -w .

build: fmt
	GOPROXY=https://athens.azurefd.net go build
	GOPROXY=https://athens.azurefd.net go build github.com/ppphp/portago/cmd/portageq

test:
	go test ./...
