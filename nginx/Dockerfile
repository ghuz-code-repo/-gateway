FROM nginx:alpine

# Install timezone data
RUN apk --no-cache add tzdata

# Set timezone
ENV TZ=Asia/Tashkent

# Create directories for configs
RUN mkdir -p /etc/nginx/conf.d/dynamic

# Copy custom entrypoint script
COPY ./docker-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

# Copy static HTML files
COPY ./html/favicon.ico /usr/share/nginx/html/favicon.ico
COPY ./html/favicon.svg /usr/share/nginx/html/favicon.svg
COPY ./html/404.html /usr/share/nginx/html/404.html

# Shared static assets (vendored JS libs served at /_shared/*)
COPY ./html/_shared /usr/share/nginx/html/_shared

EXPOSE 80 443

# Use custom entrypoint
ENTRYPOINT ["/custom-entrypoint.sh"]
