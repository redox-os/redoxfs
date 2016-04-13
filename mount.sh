#!/bin/bash
mkdir -p test

cargo run --bin redoxfs-fuse test.bin test &
