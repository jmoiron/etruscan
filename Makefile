.PHONY: all rust test fmt clean

all: rust

# Builds the static Rust library (needs Rust >= 1.82 on PATH).
rust:
	cd rust && cargo build --release
	mkdir -p lib
	cp rust/target/release/libetruscan.a lib/libetruscan.a

test: rust
	go test ./...

fmt:
	go fmt ./...

clean:
	cd rust && cargo clean
	rm -rf lib
