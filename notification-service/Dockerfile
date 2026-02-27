FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Copy static files for web interface
COPY --from=builder /app/static ./static

# Create directory for logs
RUN mkdir -p /var/log/notification-service

# Set timezone to Tashkent
ENV TZ=Asia/Tashkent

EXPOSE 80

CMD ["./main"]