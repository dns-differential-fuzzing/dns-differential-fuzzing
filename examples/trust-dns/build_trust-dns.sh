#!/bin/bash

set -eou pipefail

pushd "${PROGRAM}"

echo "Setup environment"
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

export LANG=C
export LC_LANG=C
export LANGUAGE=C

# Command line flags for rustc to enable sanitizer coverage
# https://github.com/security-geeks/afl.rs/blob/6aae34a3fae17e412419bac773ea541cd42b6c29/src/bin/cargo-afl.rs#L307-L335
# Level 3 is for edge coverage
export RUSTFLAGS=" \
    -Ccodegen-units=1 \
    -Cpasses=sancov-module \
    -Cllvm-args=-sanitizer-coverage-level=3 \
    -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
    -Cllvm-args=-sanitizer-coverage-prune-blocks=1 \
    -Clink-args=/usr/local/lib64/libcoverage.so
"

echo "Build ${PROGRAM}"
cargo build --release --features recursor --bin trust-dns
# cargo build --features recursor --bin trust-dns

echo "Install ${PROGRAM} (/usr/local)"
cp ./target/release/trust-dns /usr/local/sbin/trust-dns
# cp ./target/debug/trust-dns /usr/local/sbin/trust-dns

