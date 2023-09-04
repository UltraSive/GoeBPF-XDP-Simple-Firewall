#!/bin/bash

# Compile BPF code
clang -I ./headers -O -target bpf -c ./bpf/xdp.c -o ./bpf/xdp.o

# Build the Go program
go build -buildvcs=false

# Run the executable
./xdp-firewall
