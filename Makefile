GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o bao/plugins/bao-plugin-secrets-nebula cmd/openbao-plugin-secrets-nebula/main.go

start:
	bao server -dev -dev-root-token-id=root -dev-plugin-dir=./bao/plugins

start-vault:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bao/plugins -dev-vault

enable:
	bao secrets enable -path=nebula openbao-plugin-secrets-nebula

clean:
	rm -f ./bao/plugins/bao-plugin-secrets-nebula

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
