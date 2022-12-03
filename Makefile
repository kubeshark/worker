SHELL=/bin/bash

.PHONY: help
.DEFAULT_GOAL := build
.ONESHELL:

ARCH=$(shell uname -m)
ifeq ($(ARCH),$(filter $(ARCH),aarch64 arm64))
	BPF_TARGET=arm64
	BPF_ARCH_SUFFIX=arm64
else
	BPF_TARGET=amd64
	BPF_ARCH_SUFFIX=x86
endif

help: ## Print this help message.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the program.
	go build -ldflags="-extldflags=-static -s -w" -o worker .

bpf: ## Compile the object files for eBPF
	BPF_TARGET="$(BPF_TARGET)" BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_$(BPF_ARCH_SUFFIX)" go generate tracer/tracer.go

lint: ## Lint the source code.
	golangci-lint run

setcap:
	sudo setcap cap_net_raw,cap_net_admin,cap_sys_admin,cap_sys_ptrace,cap_sys_resource=eip ./worker

run: setcap ## Run the program. Requires Hub being available on port 8898
	./worker -i any -debug

docker-repo:
	export DOCKER_REPO='kubeshark/worker'

docker: ## Build the Docker image.
	docker build . -t ${DOCKER_REPO}:latest --build-arg BUILDARCH=amd64 --build-arg TARGETARCH=amd64

docker-push: ## Push the Docker image into Docker Hub.
	docker build . -t ${DOCKER_REPO}:latest
