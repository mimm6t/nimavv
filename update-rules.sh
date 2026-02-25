#!/bin/bash

# GFWList 和规则更新脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/rules"

mkdir -p "$RULES_DIR"

echo "📥 下载最新的 GFWList 和路由规则..."
echo ""

# 1. 下载 GFWList
echo "1️⃣  下载 GFWList..."
curl -fsSL "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt" \
    -o "$RULES_DIR/gfwlist.txt" 2>/dev/null && \
    echo "   ✅ GFWList 下载成功" || \
    echo "   ⚠️  GFWList 下载失败（使用内置规则）"

# 2. 下载中国 IP 列表
echo "2️⃣  下载中国 IP 列表..."
curl -fsSL "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt" \
    -o "$RULES_DIR/china_ip_list.txt" 2>/dev/null && \
    echo "   ✅ 中国 IP 列表下载成功" || \
    echo "   ⚠️  中国 IP 列表下载失败"

# 3. 下载中国域名列表
echo "3️⃣  下载中国域名列表..."
curl -fsSL "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf" \
    -o "$RULES_DIR/china_domains.txt" 2>/dev/null && \
    echo "   ✅ 中国域名列表下载成功" || \
    echo "   ⚠️  中国域名列表下载失败"

# 4. 下载 GeoIP 数据库
echo "4️⃣  下载 GeoLite2 数据库..."
if [ ! -f "$RULES_DIR/GeoLite2-Country.mmdb" ]; then
    echo "   ℹ️  请手动下载 GeoLite2-Country.mmdb"
    echo "   下载地址: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "   或使用: https://github.com/P3TERX/GeoLite.mmdb/releases"
    echo ""
    echo "   快速下载命令:"
    echo "   curl -L 'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb' -o '$RULES_DIR/GeoLite2-Country.mmdb'"
else
    echo "   ✅ GeoLite2 数据库已存在"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 规则文件统计:"
[ -f "$RULES_DIR/gfwlist.txt" ] && echo "   GFWList: $(wc -l < "$RULES_DIR/gfwlist.txt") 条规则"
[ -f "$RULES_DIR/china_ip_list.txt" ] && echo "   中国 IP: $(wc -l < "$RULES_DIR/china_ip_list.txt") 条"
[ -f "$RULES_DIR/china_domains.txt" ] && echo "   中国域名: $(wc -l < "$RULES_DIR/china_domains.txt") 条"
[ -f "$RULES_DIR/GeoLite2-Country.mmdb" ] && echo "   GeoIP 数据库: $(du -h "$RULES_DIR/GeoLite2-Country.mmdb" | cut -f1)"

echo ""
echo "✅ 规则更新完成"
echo ""
echo "💡 提示: 规则文件已内置到代码中，无需额外配置"
echo "   如需自定义规则，请修改 router/src/lib.rs"
