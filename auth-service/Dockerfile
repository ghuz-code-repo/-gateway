FROM golang:1.24-alpine AS builder
ENV TZ=Asia/Tashkent

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application (no CGO needed for MongoDB/Redis)
RUN CGO_ENABLED=0 GOOS=linux go build -a -o auth-service .

# Final stage
FROM alpine:3.21

# RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/auth-service .
COPY --from=builder /app/templates/ ./templates/
COPY --from=builder /app/static/ ./static/

RUN mkdir -p /data

EXPOSE 8080

CMD ["./auth-service"]
