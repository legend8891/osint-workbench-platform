#!/usr/bin/env bash
# Render build command helper (optional — dashboard can use: npm install && npm run build)
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Node $(node -v) | npm $(npm -v)"
npm install --no-audit --no-fund
npm --workspace shared run build
npm --workspace client run build
npm --workspace server run build
echo "Build OK — client/dist + server/dist ready"
ls -la client/dist server/dist shared/dist 2>/dev/null || true
