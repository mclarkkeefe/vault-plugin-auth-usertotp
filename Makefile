ARCH ?= amd64
BINDIR = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/.bin
CUSTOMGOROOT ?= $(BINDIR)/go/lib
GO ?= $(BINDIR)/go/lib/bin/go
GO_VERSION ?= 1.16.5
GOLANGCI_LINT_VERSION ?= 1.41.0
OS ?= linux
SHELL := /bin/bash

export GOPATH := $(BINDIR)/go
export GOROOT := $(CUSTOMGOROOT)
export PATH := $(BINDIR)/go/bin:$(BINDIR)/go/lib/bin:$(PATH)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	OS = darwin
endif

.PHONY: build
build: go
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -mod vendor -v

.PHONY: go
go:
	@if ! $(GO) version | grep $(GO_VERSION) > /dev/null; then \
		rm -rf .bin/go/lib; \
		mkdir -p .bin/go/lib; \
		curl -s -L https://dl.google.com/go/go$(GO_VERSION).$(OS)-amd64.tar.gz | tar -C .bin/go/lib --strip-components=1 -xz; \
		GO111MODULE=on $(GO) get golang.org/x/tools/gopls@latest; \
	fi;

.PHONY: golangci-lint
golangci-lint: go
	@if ! $(BINDIR)/golangci-lint version 2>&1 | grep $(GOLANGCI_LINT_VERSION) > /dev/null; then \
		mkdir -p .bin; \
		curl -s -L https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64.tar.gz | tar --no-same-owner -C .bin -xz --strip-components=1 golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64/golangci-lint; \
		chmod +x .bin/golangci-lint; \
	fi;
