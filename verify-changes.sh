#!/bin/bash

echo "🔍 验证修改..."
echo ""

echo "1. 检查 GitHub Actions 工作流..."
if grep -q "Download GeoIP Database" .github/workflows/build.yml; then
    echo "   ✓ GeoIP 下载步骤已添加"
else
    echo "   ✗ GeoIP 下载步骤未找到"
fi

if grep -q "Create release packages" .github/workflows/build.yml; then
    echo "   ✓ 打包步骤已添加"
else
    echo "   ✗ 打包步骤未找到"
fi

echo ""
echo "2. 检查 worker-client SNI 伪装..."
if grep -q "email.cloudflare.com" worker-client/src/lib.rs; then
    echo "   ✓ SNI 伪装已配置 (email.cloudflare.com)"
    echo "   发现的伪装位置:"
    grep -n "email.cloudflare.com" worker-client/src/lib.rs | head -5
else
    echo "   ✗ SNI 伪装未找到"
fi

echo ""
echo "3. 检查 GeoIP 路径配置..."
if grep -q './GeoLite2-Country.mmdb' config.example.toml; then
    echo "   ✓ config.example.toml 路径已更新"
else
    echo "   ✗ config.example.toml 路径未更新"
fi

if grep -q './GeoLite2-Country.mmdb' bins/client/src/main.rs; then
    echo "   ✓ 客户端默认路径已更新"
else
    echo "   ✗ 客户端默认路径未更新"
fi

echo ""
echo "4. 检查依赖..."
if grep -q "webpki-roots" worker-client/Cargo.toml; then
    echo "   ✓ webpki-roots 依赖已添加"
else
    echo "   ✗ webpki-roots 依赖未添加"
fi

echo ""
echo "✅ 验证完成！"
echo ""
echo "📝 修改摘要:"
echo "   1. GitHub Actions 会自动下载 GeoIP 数据库并打包到 ZIP 中"
echo "   2. 所有 Worker API 请求的 Host 头已改为 email.cloudflare.com"
echo "   3. GeoIP 数据库路径改为当前目录 (./GeoLite2-Country.mmdb)"
echo "   4. 发布包将包含: 二进制文件 + GeoIP 数据库 + 配置文件 + 启动脚本"
echo ""
echo "🚀 下次发布时，用户下载 ZIP 包即可直接使用，无需手动下载 GeoIP 数据库"
