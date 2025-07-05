#!/bin/bash

set -e

echo "Building eBPF program..."
cd bpftoy-ebpf
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

echo "Building userspace program..."
cd ..
cargo build --release

echo "Build complete!"
echo "Run with: sudo ./target/release/bpftoy"
