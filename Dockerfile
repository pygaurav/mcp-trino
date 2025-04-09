FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o trino-mcp ./cmd/server

# Use a small image for the final container
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/trino-mcp .

# Default environment variables
ENV TRINO_HOST="trino"
ENV TRINO_PORT="8080"
ENV TRINO_USER="trino"
ENV TRINO_CATALOG="memory"
ENV TRINO_SCHEMA="default"
ENV MCP_TRANSPORT="http"
ENV MCP_PORT="9097"

# Expose the port
EXPOSE ${MCP_PORT}

# Run the application
CMD ["./trino-mcp"] 