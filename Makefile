all: build
build:
	GOPROXY=https://athens.azurefd.net go build
	GOPROXY=https://athens.azurefd.net go build github.com/ppphp/portago/cmd/portageq
