#!/bin/bash
set -e

# Create bin directory if it doesn't exist
mkdir -p bin

# Build the server first
scripts/build.sh

# Set environment variables
export TRINO_HOST=${TRINO_HOST:-localhost}
export TRINO_PORT=${TRINO_PORT:-8080}
export TRINO_USER=${TRINO_USER:-trino}
export TRINO_CATALOG=${TRINO_CATALOG:-memory}
export TRINO_SCHEMA=${TRINO_SCHEMA:-default}
export MCP_TRANSPORT=${MCP_TRANSPORT:-stdio}
export MCP_PORT=${MCP_PORT:-9097}

echo "Starting Trino MCP Server with ${MCP_TRANSPORT} transport..."
echo "Connected to Trino at ${TRINO_HOST}:${TRINO_PORT}"

# Run the server
bin/trino-mcp 