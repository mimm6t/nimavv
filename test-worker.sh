#!/bin/bash

echo "🧪 测试 Cloudflare Worker 部署"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

WORKER_URL="https://gvbyh-worker.cflist.workers.dev"

# 1. 测试 Worker 可访问性
echo "1️⃣  测试 Worker 可访问性..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$WORKER_URL/gmail/v1/users/me/messages")
if [ "$HTTP_CODE" = "405" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "   ✅ Worker 正常运行 (HTTP $HTTP_CODE)"
else
    echo "   ❌ Worker 访问失败 (HTTP $HTTP_CODE)"
    exit 1
fi

# 2. 测试服务器列表接口
echo ""
echo "2️⃣  测试服务器列表接口..."
RESPONSE=$(curl -s "$WORKER_URL/gmail/v1/users/me/messages")
echo "   响应: $RESPONSE"
if echo "$RESPONSE" | grep -q "\["; then
    echo "   ✅ 接口返回正常（JSON 数组）"
else
    echo "   ⚠️  接口返回异常"
fi

# 3. 测试 HTTPS
echo ""
echo "3️⃣  测试 HTTPS 连接..."
if curl -s --head "$WORKER_URL" | grep -q "HTTP/2"; then
    echo "   ✅ HTTPS/2 连接正常"
else
    echo "   ⚠️  HTTPS 连接异常"
fi

# 4. 测试响应时间
echo ""
echo "4️⃣  测试响应时间..."
TIME=$(curl -s -o /dev/null -w "%{time_total}" "$WORKER_URL/gmail/v1/users/me/messages")
echo "   响应时间: ${TIME}s"
if (( $(echo "$TIME < 1.0" | bc -l) )); then
    echo "   ✅ 响应速度良好"
else
    echo "   ⚠️  响应较慢"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ Worker 部署测试完成"
echo ""
echo "📋 Worker 信息:"
echo "   URL: $WORKER_URL"
echo "   状态: 运行中"
echo ""
echo "🚀 下一步:"
echo "   1. 启动服务端: ./target/release/gvbyh-server"
echo "   2. 启动客户端: ./target/release/gvbyh-client"
echo "   3. 测试代理: curl -x socks5h://127.0.0.1:1080 https://www.google.com"
echo ""
