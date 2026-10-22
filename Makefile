.PHONY: all rust rust-local test fmt clean

all: rust

# Builds the static Rust library (needs Rust >= 1.82 on PATH).
rust:
	cd rust && cargo build --release
	mkdir -p lib
	cp rust/target/release/libetruscan.a lib/libetruscan.a

# Same, but against a local exiftool-rs checkout instead of the pinned revision
# (override with EXIFTOOL_RS=/path). Doesn't touch rust/Cargo.toml.
EXIFTOOL_RS ?= $(abspath ../exiftool-rs)
rust-local:
	cd rust && cargo build --release --config 'patch."https://github.com/Le-Syl21/exiftool-rs".exiftool-rs.path="$(EXIFTOOL_RS)"'
	mkdir -p lib
	cp rust/target/release/libetruscan.a lib/libetruscan.a

test: rust
	go test ./...

fmt:
	go fmt ./...

clean:
	cd rust && cargo clean
	rm -rf lib
