CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

all: generate build

generate:
	@echo "=> Generating eBPF Go bindings..."
	# Run go generate on the ebpf package
	go generate ./pkg/ebpf/...

build: generate
	@echo "=> Building Go control plane..."
	go build -o xdp-lb ./cmd

clean:
	@echo "=> Cleaning up..."
	rm -f xdp-lb
	rm -f pkg/ebpf/bpf_bpfel.go pkg/ebpf/bpf_bpfeb.go pkg/ebpf/bpf_bpfel.o pkg/ebpf/bpf_bpfeb.o

.PHONY: all generate build clean