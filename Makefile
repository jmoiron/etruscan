# `make` on a clean checkout builds everything: the static Rust library, then
# the Go package. Needs cargo (Rust >= 1.82) and a C toolchain; the first build
# fetches exiftool-rs from GitHub.

LIB     := lib/libetruscan.a
# Generated; holds a hash of $(LIB) in a C symbol. cgo does not track the library
# named in #cgo LDFLAGS, and Go reuses a cached link when the compiled package is
# unchanged, so a rebuilt library would otherwise be silently ignored. This file
# changes with the library, which changes the compiled package and forces a
# relink, without clearing Go's build cache.
STAMP   := etruscan_build.c
RUST_SRC := $(wildcard rust/src/*.rs) rust/Cargo.toml rust/Cargo.lock

.PHONY: all rust rust-local stamp test fmt clean
.DEFAULT_GOAL := all

all: $(STAMP)
	go build ./...

rust: $(STAMP)

$(LIB): $(RUST_SRC) | check-cargo
	cd rust && cargo build --release --locked
	mkdir -p lib
	cmp -s rust/target/release/libetruscan.a $@ || cp rust/target/release/libetruscan.a $@

$(STAMP): $(LIB)
	@$(MAKE) --no-print-directory stamp

# Writes $(STAMP) from whatever $(LIB) is now, leaving it alone if unchanged.
stamp:
	printf 'const char etruscan_lib_sha256[] = "%s";\n' "$$(sha256sum $(LIB) | cut -d' ' -f1)" > $(STAMP).tmp
	cmp -s $(STAMP).tmp $(STAMP) && rm -f $(STAMP).tmp || mv $(STAMP).tmp $(STAMP)

# Build against a local exiftool-rs checkout instead of the pinned revision
# (override with EXIFTOOL_RS=/path). Always runs cargo, since changes in that
# checkout are not tracked here. rust/Cargo.lock is put back afterwards.
EXIFTOOL_RS ?= $(abspath ../exiftool-rs)
rust-local: | check-cargo
	cp rust/Cargo.lock rust/Cargo.lock.orig
	cd rust && cargo build --release --config 'patch."https://github.com/jmoiron/exiftool-rs".exiftool-rs.path="$(EXIFTOOL_RS)"'; \
		status=$$?; mv Cargo.lock.orig Cargo.lock; exit $$status
	mkdir -p lib
	cmp -s rust/target/release/libetruscan.a $(LIB) || cp rust/target/release/libetruscan.a $(LIB)
	$(MAKE) --no-print-directory stamp
	go build ./...

test: all
	go test ./...

fmt:
	go fmt ./...

clean:
	cd rust && cargo clean
	rm -rf lib $(STAMP)

.PHONY: check-cargo
check-cargo:
	@command -v cargo >/dev/null || { echo "cargo not found: install Rust >= 1.82 (https://rustup.rs)" >&2; exit 1; }
