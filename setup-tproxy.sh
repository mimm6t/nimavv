#!/bin/bash

# TProxy 透明代理配置脚本（支持 IPv4/IPv6）

if [ "$EUID" -ne 0 ]; then 
    echo "❌ 请使用 root 权限运行此脚本"
    echo "   sudo $0"
    exit 1
fi

TPROXY_PORT=12345
TPROXY_MARK=0x1

echo "🔧 配置透明代理 (TProxy)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 检查内核模块
echo "1️⃣  检查内核模块..."
modprobe xt_TPROXY 2>/dev/null
modprobe xt_socket 2>/dev/null
modprobe xt_mark 2>/dev/null

if lsmod | grep -q xt_TPROXY; then
    echo "   ✅ xt_TPROXY 模块已加载"
else
    echo "   ⚠️  xt_TPROXY 模块加载失败"
fi

# IPv4 配置
echo ""
echo "2️⃣  配置 IPv4 透明代理..."

# 清理旧规则
iptables -t mangle -F 2>/dev/null
iptables -t mangle -X 2>/dev/null

# 创建 TPROXY 规则
iptables -t mangle -N GVBYH 2>/dev/null

# 跳过本地流量
iptables -t mangle -A GVBYH -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A GVBYH -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A GVBYH -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A GVBYH -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A GVBYH -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A GVBYH -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A GVBYH -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A GVBYH -d 240.0.0.0/4 -j RETURN

# TPROXY 重定向
iptables -t mangle -A GVBYH -p tcp -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK

# 应用规则
iptables -t mangle -A PREROUTING -j GVBYH

echo "   ✅ IPv4 iptables 规则已配置"

# IPv6 配置
echo ""
echo "3️⃣  配置 IPv6 透明代理..."

# 清理旧规则
ip6tables -t mangle -F 2>/dev/null
ip6tables -t mangle -X 2>/dev/null

# 创建 TPROXY 规则
ip6tables -t mangle -N GVBYH 2>/dev/null

# 跳过本地流量
ip6tables -t mangle -A GVBYH -d ::1/128 -j RETURN
ip6tables -t mangle -A GVBYH -d fe80::/10 -j RETURN
ip6tables -t mangle -A GVBYH -d fc00::/7 -j RETURN

# TPROXY 重定向
ip6tables -t mangle -A GVBYH -p tcp -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK

# 应用规则
ip6tables -t mangle -A PREROUTING -j GVBYH

echo "   ✅ IPv6 ip6tables 规则已配置"

# 路由配置
echo ""
echo "4️⃣  配置路由规则..."

# IPv4 路由
ip rule del fwmark $TPROXY_MARK lookup 100 2>/dev/null
ip rule add fwmark $TPROXY_MARK lookup 100
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
ip route add local 0.0.0.0/0 dev lo table 100

echo "   ✅ IPv4 路由规则已配置"

# IPv6 路由
ip -6 rule del fwmark $TPROXY_MARK lookup 100 2>/dev/null
ip -6 rule add fwmark $TPROXY_MARK lookup 100
ip -6 route del local ::/0 dev lo table 100 2>/dev/null
ip -6 route add local ::/0 dev lo table 100

echo "   ✅ IPv6 路由规则已配置"

# 系统参数
echo ""
echo "5️⃣  配置系统参数..."

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null

echo "   ✅ 系统参数已配置"

# 验证配置
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ 透明代理配置完成"
echo ""
echo "📋 配置信息:"
echo "   TProxy 端口: $TPROXY_PORT"
echo "   标记值: $TPROXY_MARK"
echo ""
echo "🧪 测试命令:"
echo "   # 启动客户端（启用 TProxy）"
echo "   ./target/release/gvbyh-client --config config.toml"
echo ""
echo "   # 测试连接"
echo "   curl http://www.google.com"
echo "   curl -6 http://ipv6.google.com"
echo ""
echo "🔄 清理配置:"
echo "   sudo $0 clean"
echo ""

# 清理模式
if [ "$1" = "clean" ]; then
    echo "🧹 清理透明代理配置..."
    
    iptables -t mangle -D PREROUTING -j GVBYH 2>/dev/null
    iptables -t mangle -F GVBYH 2>/dev/null
    iptables -t mangle -X GVBYH 2>/dev/null
    
    ip6tables -t mangle -D PREROUTING -j GVBYH 2>/dev/null
    ip6tables -t mangle -F GVBYH 2>/dev/null
    ip6tables -t mangle -X GVBYH 2>/dev/null
    
    ip rule del fwmark $TPROXY_MARK lookup 100 2>/dev/null
    ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
    
    ip -6 rule del fwmark $TPROXY_MARK lookup 100 2>/dev/null
    ip -6 route del local ::/0 dev lo table 100 2>/dev/null
    
    echo "✅ 清理完成"
fi
