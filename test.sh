#!/usr/bin/env bash

CARGO_ARGS=(--release)
TARGET=target/release
export RUST_BACKTRACE=full
export RUST_LOG=info

function cleanup {
    sync
    fusermount -u image || true
}

trap 'cleanup' ERR

set -eEx

cleanup

redoxer test -- --lib -- --nocapture
cargo test --lib --no-default-features -- --nocapture
cargo test --lib -- --nocapture
cargo build "${CARGO_ARGS[@]}"

rm -f image.bin
fallocate -l 1G image.bin
time "${TARGET}/redoxfs-mkfs" image.bin

mkdir -p image
"${TARGET}/redoxfs" image.bin image

df -h image
ls -lah image

mkdir image/test
time cp -r src image/test/src
dd if=/dev/urandom of=image/test/random bs=1M count=256
dd if=image/test/random of=/dev/null bs=1M count=256
dd if=/dev/zero of=image/test/zero bs=1M count=256
dd if=image/test/zero of=/dev/null bs=1M count=256
ls -lah image/test

df -h image

rm image/test/random
rm image/test/zero
rm -rf image/test/src
rmdir image/test

df -h image
ls -lah image

cleanup

"${TARGET}/redoxfs" image.bin image

df -h image
ls -lah image

cleanup
