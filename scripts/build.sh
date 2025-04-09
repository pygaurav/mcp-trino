#!/bin/bash
set -e

echo "Building Trino MCP Server..."
go build -o bin/trino-mcp cmd/server/main.go

echo "Build complete!" 