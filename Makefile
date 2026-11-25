all: build

generate:
	@echo "=> Generating eBPF Go bindings..."
	go generate ./pkg/ebpf/...

build: generate
	@echo "=> Building Go control plane..."
	go build -o xdp-lb ./cmd

test: generate
	go test ./...

clean:
	@echo "=> Cleaning up..."
	rm -f xdp-lb
	rm -f pkg/ebpf/bpf_bpfel.go pkg/ebpf/bpf_bpfeb.go pkg/ebpf/bpf_bpfel.o pkg/ebpf/bpf_bpfeb.o

.PHONY: all generate build test clean
