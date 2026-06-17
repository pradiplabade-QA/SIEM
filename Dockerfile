FROM golang:1.26.3-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -o siem ./cmd/siem

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/siem .
COPY --from=builder /app/Frontend ./Frontend
EXPOSE 8080
CMD ["./siem"]