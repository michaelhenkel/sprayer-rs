.PHONY: sprayer  server client cli_client cli_server
ARCH?=aarch64
all: sprayer server client cli_client cli_server
sprayer: ebpf
	(cd sprayer; cargo build --release --target=${ARCH}-unknown-linux-gnu)
ebpf:
	(cd sprayer; cargo xtask build-ebpf --release)
server:
	(cd server; cargo build --release --target=${ARCH}-unknown-linux-gnu)
client:
	(cd client; cargo build --release --target=${ARCH}-unknown-linux-gnu)
cli_client:
	(cd cli_client; cargo build --release --target=${ARCH}-unknown-linux-gnu)
cli_server:
	(cd cli_server; cargo build --release --target=${ARCH}-unknown-linux-gnu)
copy:
	(scp \
	  sprayer/target/aarch64-unknown-linux-musl/release/sprayer \
	  target/aarch64-unknown-linux-musl/release/server \
	  192.168.105.6:)
