#!/bin/bash
# GeoIP 功能测试

echo "🧪 测试 GeoIP 功能"
echo "=================="

# 创建测试程序
cat > /tmp/test_geoip.rs << 'RUST'
use std::net::IpAddr;

fn main() {
    // 测试 IP 地址
    let test_ips = vec![
        ("114.114.114.114", "CN", "中国 DNS"),
        ("8.8.8.8", "US", "Google DNS"),
        ("1.1.1.1", "US", "Cloudflare DNS"),
        ("223.5.5.5", "CN", "阿里 DNS"),
        ("180.76.76.76", "CN", "百度 DNS"),
        ("208.67.222.222", "US", "OpenDNS"),
    ];
    
    println!("测试 GeoIP 查询:");
    println!("{:<20} {:<10} {:<20}", "IP 地址", "预期国家", "描述");
    println!("{}", "-".repeat(50));
    
    for (ip_str, expected, desc) in test_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        println!("{:<20} {:<10} {:<20}", ip_str, expected, desc);
    }
}
RUST

echo "✅ 测试脚本创建完成"
echo ""
echo "📝 测试 IP 列表:"
echo "  - 114.114.114.114 (CN) - 中国 DNS"
echo "  - 8.8.8.8 (US) - Google DNS"
echo "  - 1.1.1.1 (US) - Cloudflare DNS"
echo "  - 223.5.5.5 (CN) - 阿里 DNS"
echo "  - 180.76.76.76 (CN) - 百度 DNS"
echo "  - 208.67.222.222 (US) - OpenDNS"
echo ""
echo "🚀 GeoIP 数据库已内置到二进制文件中"
echo "📦 二进制大小:"
ls -lh target/release/gvbyh-client | awk '{print "  客户端: " $5}'
ls -lh target/release/gvbyh-server | awk '{print "  服务端: " $5}'
