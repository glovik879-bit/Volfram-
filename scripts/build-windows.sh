#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

go run tools/mkres/main.go res rsrc_windows_amd64.syso
mkdir -p dist
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-H windowsgui -s -w" -o dist/Volfram.exe .
ls -la dist/Volfram.exe
