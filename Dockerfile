FROM golang:1.22 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app

FROM registry.access.redhat.com/ubi8/ubi

WORKDIR /app
COPY --from=builder /app/app /app/app

RUN chmod +x /app/app

EXPOSE 8080
CMD ["/app/app"]

