# GoeBPF-XDP-Simple-Firewall
- Universal Source Address Rules (Block / Allow)
- Source Address & Destination Address Pair (Block / Allow)
- Port:Protocol Punching (Block / Allow) per Destination Address
- Default Behavior (Block / Allow) per Destination Address

## Requirements
- Linux 5.3+
- GoLang 1.18+

## Usage
Compile the BPF bytecode to a ELF file.
```bash
clang -I ./headers -O -target bpf -c ./bpf/xdp.c -o ./bpf/xdp.o
```
Build the go program.
```bash
go build
```
Run the go program.
```bash
./xdp-firewall
```

## To Do
- Ratelimiting / Port:Protocol
- AF_XDP Socket Redirecting
- Pulling rules from database established in environment variables.
- Modification of rule maps while running.
- Dockerfile to load and run userspace go code.
