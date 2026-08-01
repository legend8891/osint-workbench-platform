#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "==> Installing dependencies"
npm install --no-audit --no-fund
echo "==> Building shared, client, server"
npm run build
echo "==> Starting production server on PORT=${PORT:-8787}"
export NODE_ENV=production
exec node server/dist/index.js
