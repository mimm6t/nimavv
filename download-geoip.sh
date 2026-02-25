#!/bin/bash
# 下载 GeoLite2 Country 数据库（用于本地开发）

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/router/data"

mkdir -p "$DATA_DIR"

echo "Downloading GeoLite2-Country database..."

curl -L -o "$DATA_DIR/GeoLite2-Country.mmdb" \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb

echo "✓ Downloaded successfully"
ls -lh "$DATA_DIR/GeoLite2-Country.mmdb"

