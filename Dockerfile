# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o cloaker ./cmd/server

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' cloaker

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/cloaker .

# Copy data files
COPY --from=builder /app/data ./data

# Create data directory for SQLite
RUN mkdir -p /app/data/db && chown -R cloaker:cloaker /app

# Switch to non-root user
USER cloaker

# Expose port (App Platform uses $PORT env var)
EXPOSE 8080

# Health check using /health endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-8080}/health || exit 1

# Run the application (PORT is set by App Platform)
ENTRYPOINT ["./cloaker"]

