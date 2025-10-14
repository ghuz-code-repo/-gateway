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

# Install timezone data, ca-certificates, and docker CLI
RUN apk --no-cache add ca-certificates tzdata docker-cli

# Set timezone
ENV TZ=Asia/Tashkent

WORKDIR /root/

# Create data directory for volumes BEFORE copying files
RUN mkdir -p /root/data

COPY --from=builder /app/auth-service .
COPY --from=builder /app/templates/ ./templates/
COPY --from=builder /app/static/ ./static/
COPY --from=builder /app/resources/ ./resources/

EXPOSE 8080

CMD ["./auth-service"]
