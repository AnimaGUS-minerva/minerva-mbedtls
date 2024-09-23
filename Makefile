all: build

.PHONY: test

SHELL := /bin/bash

# 'test' or 'ci'
TARGET ?= test
ci:
	##TARGET=ci make test
	TARGET=ci make test-x86_64 test-x86  # WIP with rust-psa-crypto--0.12.0-minerva

init-rust-toolchains:
	rustup toolchain install nightly-x86_64-unknown-linux-gnu
	rustup toolchain install nightly-i686-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-gnu
	rustup target add i686-unknown-linux-gnu --toolchain nightly
	rustup default nightly
	rustup show

NAMES := voucher-x86_64-std voucher-x86-no_std
test-examples:
	for name in $(NAMES); do \
        make -C ./examples/$$name test || exit 1; done

test-x86_64:
	cargo build --lib --release
	cargo test --manifest-path ./test/Cargo.toml
	cargo test --manifest-path ./test/Cargo.toml --no-default-features --features "std"

test-x86:
	cargo build --lib --release --target i686-unknown-linux-gnu
	cargo test --manifest-path ./test/Cargo.toml --target i686-unknown-linux-gnu
	cargo test --manifest-path ./test/Cargo.toml --no-default-features --features "std" --target i686-unknown-linux-gnu

test:
	make test-x86_64
	make test-x86
	make test-examples
