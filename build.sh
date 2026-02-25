#!/bin/bash
set -e

echo "==================================="
echo "gvbyh-rust 构建脚本"
echo "Rust版本: $(cargo --version)"
echo "==================================="

# 检查Rust版本
REQUIRED_VERSION="1.95.0"
CURRENT_VERSION=$(cargo --version | grep -oP '\d+\.\d+\.\d+' | head -1)

if [[ "$CURRENT_VERSION" != "$REQUIRED_VERSION"* ]]; then
    echo "警告: 当前Rust版本 $CURRENT_VERSION 不匹配要求的 $REQUIRED_VERSION"
    echo "建议运行: rustup install nightly-2026-01-30"
fi

# 目标架构
TARGETS=(
    "x86_64-unknown-linux-musl"      # x86_64测试
    "mipsel-unknown-linux-musl"      # MT7621等MIPS路由器
    "arm-unknown-linux-musleabi"     # ARMv5/v6
    "armv7-unknown-linux-musleabihf" # ARMv7
    "aarch64-unknown-linux-musl"     # ARMv8/ARM64
)

# 构建类型
BUILD_TYPE="${1:-release}"

if [[ "$BUILD_TYPE" == "debug" ]]; then
    BUILD_FLAG=""
    BUILD_DIR="debug"
else
    BUILD_FLAG="--release"
    BUILD_DIR="release"
fi

echo ""
echo "构建类型: $BUILD_TYPE"
echo ""

# 添加目标
echo "添加编译目标..."
for target in "${TARGETS[@]}"; do
    rustup target add "$target" 2>/dev/null || true
done

# 创建输出目录
mkdir -p dist

# 编译函数
build_target() {
    local target=$1
    local name=$2
    local features=$3
    
    echo ""
    echo ">>> 编译 $name for $target..."
    
    if [[ -n "$features" ]]; then
        cargo build $BUILD_FLAG --target "$target" -p "$name" --features "$features"
    else
        cargo build $BUILD_FLAG --target "$target" -p "$name"
    fi
    
    local binary="target/$target/$BUILD_DIR/$name"
    
    if [[ -f "$binary" ]]; then
        local size=$(du -h "$binary" | cut -f1)
        echo "✓ 编译成功: $binary ($size)"
        
        # 复制到dist目录
        cp "$binary" "dist/${name}-${target}"
        
        # 压缩 (仅release模式)
        if [[ "$BUILD_TYPE" == "release" ]] && command -v upx &> /dev/null; then
            echo "  压缩中..."
            upx --best --lzma "dist/${name}-${target}" 2>/dev/null || true
            local compressed_size=$(du -h "dist/${name}-${target}" | cut -f1)
            echo "  压缩后: $compressed_size"
        fi
    else
        echo "✗ 编译失败"
        return 1
    fi
}

# 编译所有目标
for target in "${TARGETS[@]}"; do
    echo ""
    echo "======================================="
    echo "目标架构: $target"
    echo "======================================="
    
    # 完整客户端
    build_target "$target" "gvbyh-client" ""
    
    # 仅透明代理 (可选)
    # build_target "$target" "gvbyh-tproxy" "tproxy"
    
    # 仅DNS (可选)
    # build_target "$target" "gvbyh-dns" "dns"
done

echo ""
echo "======================================="
echo "构建完成!"
echo "======================================="
echo ""
echo "输出目录: dist/"
ls -lh dist/
echo ""

# 生成SHA256校验和
if command -v sha256sum &> /dev/null; then
    echo "生成SHA256校验和..."
    cd dist
    sha256sum * > SHA256SUMS
    cd ..
    echo "✓ SHA256SUMS 已生成"
fi

echo ""
echo "使用示例:"
echo "  # 上传到OpenWrt路由器"
echo "  scp dist/gvbyh-client-mipsel-unknown-linux-musl root@192.168.1.1:/usr/bin/gvbyh-client"
echo ""
echo "  # 运行"
echo "  gvbyh-client --config /etc/gvbyh/config.toml"
echo ""
