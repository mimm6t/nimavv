#!/bin/bash

# Cloudflare 配置
ACCOUNT_ID="b6fb628a1e803dd7798650f4f35314d1"
API_TOKEN="9xLoKTXn372u0gCUAqL4ucVJoh5gPi3kzJ_SEh_T"
EMAIL="dagax16118@exitbit.com"
WORKER_NAME="gvbyh-worker"
CUSTOM_DOMAIN="mirrors.ustc.ip-ddns.com"

echo "🔍 检查域名 DNS 配置..."
dig +short $CUSTOM_DOMAIN

echo ""
echo "📋 获取 Worker 信息..."
curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" | jq .

echo ""
echo "🌐 获取域名的 Zone ID..."
ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=ip-ddns.com" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json")

ZONE_ID=$(echo $ZONE_RESPONSE | jq -r '.result[0].id')

if [ "$ZONE_ID" = "null" ] || [ -z "$ZONE_ID" ]; then
  echo "❌ 域名 ip-ddns.com 未在此 Cloudflare 账户中找到"
  echo "解决方案："
  echo "1. 确保域名在 Cloudflare 中托管"
  echo "2. 或使用 workers.dev 子域名"
  exit 1
fi

echo "✅ Zone ID: $ZONE_ID"

echo ""
echo "🔧 配置 Worker 自定义域名..."
curl -s -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/domains" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{
    \"hostname\": \"$CUSTOM_DOMAIN\",
    \"service\": \"$WORKER_NAME\",
    \"environment\": \"production\"
  }" | jq .

echo ""
echo "🔐 检查 SSL 设置..."
curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/ssl" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" | jq .

echo ""
echo "✅ 设置 SSL 为 Full..."
curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/ssl" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"full"}' | jq .

echo ""
echo "🎯 测试访问..."
echo "HTTP: curl -I http://$CUSTOM_DOMAIN"
echo "HTTPS: curl -I https://$CUSTOM_DOMAIN"
