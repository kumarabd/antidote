#!/usr/bin/env bash
# Build Antidote UI for production
set -e
cd "$(dirname "$0")/../ui"
npm ci
npm run build
