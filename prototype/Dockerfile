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

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy compiled binary & static frontend assets
COPY --from=builder /build/server /app/server
COPY static /app/static

EXPOSE 8443

ENV PORT=8443

CMD ["/app/server"]
