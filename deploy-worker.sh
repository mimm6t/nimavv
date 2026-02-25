#!/bin/bash
set -e

echo "=== Deploying Worker to Cloudflare ==="

# 设置环境变量（仅本次会话有效）
export CLOUDFLARE_API_TOKEN="9xLoKTXn372u0gCUAqL4ucVJoh5gPi3kzJ_SEh_T"
export CLOUDFLARE_ACCOUNT_ID="b6fb628a1e803dd7798650f4f35314d1"

# 进入 worker 目录
cd worker

# 检查 wrangler 是否安装
if ! command -v wrangler &> /dev/null; then
    echo "Installing wrangler..."
    npm install -g wrangler
fi

# 登录验证
echo "Verifying authentication..."
wrangler whoami

# 部署 Worker
echo "Deploying worker..."
wrangler deploy

echo "=== Deployment Complete ==="
echo "Worker URL: https://gvbyh-worker.cflist.workers.dev"
echo "Custom Domain: http://mirrors.ustc.ip-ddns.com"
