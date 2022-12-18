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
	sudo setcap cap_net_raw,cap_net_admin,cap_sys_admin,cap_sys_ptrace,cap_dac_override,cap_sys_resource=eip ./worker

run: setcap ## Run the program. Requires Hub being available on port 8898
	./worker -i any -port 8897 -debug

run-tls: setcap ## Run the program with TLS capture enabled. Requires Hub being available on port 8898
	KUBESHARK_GLOBAL_LIBSSL_PID=$(shell ps -ef | awk '$$8=="python3" && $$9=="tls.py" {print $$2}') \
		./worker -i any -port 8897 -debug -tls

docker: ## Build the Docker image.
	docker build . -t ${DOCKER_REPO}:${DOCKER_TAG} --build-arg BUILDARCH=amd64 --build-arg TARGETARCH=amd64

docker-push: ## Push the Docker image into Docker Hub.
	docker push ${DOCKER_REPO}:${DOCKER_TAG}

docker-dev-build: ## Build the dev Docker image. (pulls less, faster)
	docker build -f Dockerfile.dev . -t ${DOCKER_REPO}:${DOCKER_TAG} --build-arg TARGETARCH=amd64

docker-latest: ## Build and push the Docker image with 'latest' tag
	export DOCKER_REPO='kubeshark/worker' && \
	export DOCKER_TAG='latest' && \
	${MAKE} docker && \
	${MAKE} docker-push

docker-canary: ## Build and push the Docker image with 'canary' tag
	export DOCKER_REPO='kubeshark/worker' && \
	export DOCKER_TAG='canary' && \
	${MAKE} docker && \
	${MAKE} docker-push

docker-dev: ## Build and push the Docker image with 'dev' tag
	export DOCKER_REPO='kubeshark/worker' && \
	export DOCKER_TAG='dev' && \
	${MAKE} docker-dev-build && \
	${MAKE} docker-push

docker-canary-retag-dev-do:
	docker pull ${DOCKER_REPO}:canary && \
	docker image tag ${DOCKER_REPO}:canary ${DOCKER_REPO}:dev && \
	docker push ${DOCKER_REPO}:dev

docker-canary-retag-dev: ## Pull the canary release and push it as dev
	export DOCKER_REPO='kubeshark/worker' && \
	${MAKE} docker-canary-retag-dev-do
