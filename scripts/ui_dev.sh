#!/usr/bin/env bash
# Run Vite dev server for Antidote UI (with proxy to daemon)
set -e
cd "$(dirname "$0")/../ui"
if [ ! -d node_modules ]; then
  npm install
fi
npm run dev
