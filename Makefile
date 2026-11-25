all: build

generate:
	@echo "=> Generating eBPF Go bindings..."
	go generate ./pkg/ebpf/...

build: generate
	@echo "=> Building Go control plane..."
	go build -o xdp-lb ./cmd

test: generate
	go test ./...

bench: generate
	go test ./pkg/ebpf -run '^$$' -bench . -count 5

clean:
	@echo "=> Cleaning up..."
	rm -f xdp-lb
	rm -f pkg/ebpf/bpf_bpfel.go pkg/ebpf/bpf_bpfeb.go pkg/ebpf/bpf_bpfel.o pkg/ebpf/bpf_bpfeb.o

.PHONY: all generate build test bench clean
