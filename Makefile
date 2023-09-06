.PHONY: sprayer  server
ARCH := aarch64
all: sprayer server copy
sprayer: ebpf
	(cd sprayer; RUSTFLAGS="-Clinker=${ARCH}-linux-musl-ld" cargo build --release --target=${ARCH}-unknown-linux-musl)
ebpf:
	(cd sprayer;cargo xtask build-ebpf --release)
server:
	(cd server; RUSTFLAGS="-Clinker=${ARCH}-linux-musl-ld" cargo build --release --target=${ARCH}-unknown-linux-musl)
copy:
	(scp \
	  sprayer/target/aarch64-unknown-linux-musl/release/sprayer \
	  target/aarch64-unknown-linux-musl/release/server \
	  192.168.105.5:)
