# ---------- Build stage ----------
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# ---------- Runtime stage ----------
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary
COPY --from=builder /app/main /app/main

# 🔴 THIS IS THE CRITICAL LINE 🔴
RUN chmod 755 /app/main

EXPOSE 8080

# Run as non-root compatible
USER 1001

CMD ["/app/main"]
