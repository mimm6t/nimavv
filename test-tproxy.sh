#!/bin/bash
# 透明代理测试脚本

set -e

TPROXY_PORT=12345
TPROXY_MARK=0x1

echo "🧪 测试透明代理功能"
echo "===================="

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ 请使用 root 权限运行此脚本"
    exit 1
fi

# 检查内核模块
echo "📦 检查内核模块..."
modprobe xt_TPROXY 2>/dev/null || echo "⚠️  xt_TPROXY 模块加载失败"
modprobe xt_socket 2>/dev/null || echo "⚠️  xt_socket 模块加载失败"

# 清理旧规则
echo "🧹 清理旧规则..."
iptables -t mangle -F 2>/dev/null || true
ip rule del fwmark $TPROXY_MARK table 100 2>/dev/null || true
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

# 设置路由表
echo "🛣️  设置路由表..."
ip rule add fwmark $TPROXY_MARK table 100
ip route add local 0.0.0.0/0 dev lo table 100

# 设置 iptables 规则
echo "🔧 设置 iptables 规则..."

# TCP 透明代理
iptables -t mangle -A PREROUTING -p tcp -m socket -j MARK --set-mark $TPROXY_MARK
iptables -t mangle -A PREROUTING -p tcp -m mark ! --mark $TPROXY_MARK -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK

# UDP 透明代理
iptables -t mangle -A PREROUTING -p udp -m socket -j MARK --set-mark $TPROXY_MARK
iptables -t mangle -A PREROUTING -p udp -m mark ! --mark $TPROXY_MARK -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK

echo "✅ 透明代理规则设置完成"
echo ""
echo "📋 当前规则:"
echo "============"
iptables -t mangle -L PREROUTING -n -v
echo ""
echo "📋 路由规则:"
echo "============"
ip rule show
echo ""
echo "📋 路由表 100:"
echo "============"
ip route show table 100
echo ""
echo "🎯 测试命令:"
echo "============"
echo "TCP 测试: curl -v http://example.com"
echo "UDP 测试: dig @8.8.8.8 example.com"
echo ""
echo "🔍 查看日志: journalctl -u gvbyh-client -f"
echo ""
echo "🛑 清理规则: $0 clean"
