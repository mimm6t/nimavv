#!/bin/bash

# Cloudflare 配置
ACCOUNT_ID="b6fb628a1e803dd7798650f4f35314d1"
API_TOKEN="9xLoKTXn372u0gCUAqL4ucVJoh5gPi3kzJ_SEh_T"
WORKER_NAME="gvbyh-worker"

echo "📋 当前 Worker 域名配置："
echo ""
echo "✅ 可用的 HTTPS 域名："
echo "   https://gvbyh-worker.cflist.workers.dev"
echo ""
echo "❌ 不可用的域名（不在你的账户中）："
echo "   http://mirrors.ustc.ip-ddns.com"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔧 如何添加自定义域名："
echo ""
echo "1. 在 Cloudflare 添加你自己的域名："
echo "   https://dash.cloudflare.com/$ACCOUNT_ID/add-site"
echo ""
echo "2. 或者使用 Cloudflare Workers 自定义域名："
echo "   https://dash.cloudflare.com/$ACCOUNT_ID/workers/services/view/$WORKER_NAME/production/settings/domains"
echo ""
echo "3. 临时方案：使用 workers.dev 域名（已支持 HTTPS）"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🧪 测试当前 Worker："
echo ""

echo "测试 workers.dev 域名..."
curl -s -I https://gvbyh-worker.cflist.workers.dev/gmail/v1/users/me/messages | head -5

echo ""
echo "✅ 已将代码中的默认 URL 改为 HTTPS workers.dev 域名"
