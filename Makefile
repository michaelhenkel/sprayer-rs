.PHONY: sprayer  server client
ARCH := aarch64
all: sprayer server client
sprayer: ebpf
	(cd sprayer; CARGO_TARGET_DIR=/tmp/lima cargo build --release --target=${ARCH}-unknown-linux-gnu)
ebpf:
	(cd sprayer; CARGO_TARGET_DIR=/tmp/lima cargo xtask build-ebpf --release)
server:
	(cd server; CARGO_TARGET_DIR=/tmp/lima cargo build --release --target=${ARCH}-unknown-linux-gnu)
client:
	(cd client; CARGO_TARGET_DIR=/tmp/lima cargo build --release --target=${ARCH}-unknown-linux-gnu)
copy:
	(scp \
	  sprayer/target/aarch64-unknown-linux-musl/release/sprayer \
	  target/aarch64-unknown-linux-musl/release/server \
	  192.168.105.6:)
