# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy all source code
COPY . .

# Generate go.sum and download dependencies
RUN go mod tidy && go mod download

# Build the binary (static linking for Alpine)
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o cloaker ./cmd/server

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata wget

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/cloaker .

# Copy data files (JSON detection data)
COPY --from=builder /app/data ./data

# Ensure data directory is writable for SQLite database
RUN chmod +x ./cloaker && chmod -R 777 ./data

# Expose port
EXPOSE 8080

# Run the application
CMD ["./cloaker"]
