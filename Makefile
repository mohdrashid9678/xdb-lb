# Makefile
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

all: generate build

generate:
	@echo "=> Generating eBPF Go bindings..."
	go generate ./cmd/...

build: generate
	@echo "=> Building Go control plane..."
	go build -o xdp-lb ./cmd/main.go

clean:
	@echo "=> Cleaning up..."
	rm -f xdp-lb
	rm -f cmd/bpf_bpfel.go cmd/bpf_bpfeb.go cmd/bpf_bpfel.o cmd/bpf_bpfeb.o

.PHONY: all generate build clean