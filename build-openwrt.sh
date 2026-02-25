#!/bin/bash
set -e

echo "Building gvbyh-rust for OpenWrt..."

# 目标架构
TARGETS=(
    "mipsel-unknown-linux-musl"      # MT7621等
    "arm-unknown-linux-musleabi"     # ARMv5/v6
    "armv7-unknown-linux-musleabihf" # ARMv7
    "aarch64-unknown-linux-musl"     # ARMv8/ARM64
)

# 添加目标
for target in "${TARGETS[@]}"; do
    rustup target add "$target"
done

# 编译
for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    
    # 完整客户端
    cargo build --release --target "$target" -p gvbyh-client
    
    # 仅透明代理
    cargo build --release --target "$target" -p gvbyh-tproxy \
        --no-default-features --features tproxy
    
    # 仅DNS
    cargo build --release --target "$target" -p gvbyh-dns \
        --no-default-features --features dns
    
    # 压缩
    upx --best --lzma "target/$target/release/gvbyh-client" || true
    upx --best --lzma "target/$target/release/gvbyh-tproxy" || true
    upx --best --lzma "target/$target/release/gvbyh-dns" || true
done

echo "Build complete!"
echo "Binaries in target/<arch>/release/"
