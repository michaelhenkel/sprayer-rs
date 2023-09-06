.PHONY: tc-egress xdp-ingress
ARCH := aarch64
all: tc-egress xdp-ingress
tc-egress: tc-egress-ebpf
	(cd tc-egress; RUSTFLAGS="-Clinker=${ARCH}-linux-musl-ld" cargo build --release --target=${ARCH}-unknown-linux-musl)
tc-egress-ebpf:
	(cd tc-egress;cargo xtask build-ebpf --release)
xdp-ingress: xdp-ingress-ebpf
	(cd xdp-ingress; RUSTFLAGS="-Clinker=${ARCH}-linux-musl-ld" cargo build --release --target=${ARCH}-unknown-linux-musl)
xdp-ingress-ebpf:
	(cd xdp-ingress;cargo xtask build-ebpf --release)
