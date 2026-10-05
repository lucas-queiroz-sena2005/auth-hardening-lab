# Multi-stage Dockerfile for Headless Execution
FROM docker.io/library/golang:1.23-alpine AS builder

WORKDIR /build

# Copy dependency definition & source code
COPY go.mod ./
COPY main.go ./

# Download dependencies & compile static binary
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server main.go

# Production Runtime Container
FROM docker.io/library/alpine:latest

# Install runtime packages and create unprivileged non-root appuser (UID 10001)
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 appuser

WORKDIR /app

# Create data directory for SQLite & TLS assets
RUN mkdir -p /app/data

# Copy compiled binary & static frontend assets
COPY --from=builder /build/server /app/server
COPY static /app/static

# Set directory ownership to unprivileged user
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8443

ENV PORT=8443

CMD ["/app/server"]
