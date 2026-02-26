# ===================================================================
# GATEWAY & AUTH-SERVICE CORE CONFIGURATION
# ===================================================================
# This file contains the core gateway configuration including:
# - Authentication endpoints (login, logout, password recovery)
# - Admin panel (users, roles, permissions, services)
# - Common endpoints (menu, profile, static files)
# - Internal auth verification endpoint
# ===================================================================

# ================================================================
# EXTERNAL SERVICE UPSTREAMS (not part of gateway service discovery)
# ================================================================
upstream apartment-finder {
    server apartment-finder-app:5000;
}

# Redirect HTTP -> HTTPS
server {
    listen 80;
    server_name analytics.gh.uz localhost;
    return 301 https://$host$request_uri;
}

# Main HTTPS server
server {
    listen 443 ssl;
    server_name analytics.gh.uz localhost;

    # SSL Configuration - use certs mounted into the container
    ssl_certificate /etc/nginx/certs/gh.uz.chain.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    client_max_body_size 100M;
    add_header X-Debug-Message "Request processed by Nginx" always;

    # ================================================================
    # FAVICON CONFIGURATION
    # ================================================================
    
    # Insert favicon with unique tag
    sub_filter_once off;
    sub_filter_types text/html;
    sub_filter '</head>' '<link rel="icon" type="image/x-icon" href="/vite.svg?v=2" data-version="golden-house-v2"></head>';
    
    # Main favicon endpoints - proxy to auth-service
    location = /vite.svg {
        proxy_pass http://auth-service:80/vite.svg;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Content-Type "image/x-icon" always;
        add_header Cache-Control "public, max-age=3600" always;
        expires 1h;
        access_log off;
    }
    
    location = /favicon.svg {
        root /usr/share/nginx/html;
        add_header Content-Type "image/svg+xml" always;
        add_header Cache-Control "public, max-age=604800, immutable" always;
        expires 7d;
        access_log off;
    }
    
    # Block PNG favicon requests
    location ~ ^/static/img/favicon\.(ico|png)$ {
        return 404;
    }
    
    # Block logo.png when used as favicon
    location ~ ^/static/img/logo\.png$ {
        if ($http_referer ~ favicon) {
            return 404;
        }
        proxy_pass http://auth-service:80$request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_valid 200 24h;
        add_header Cache-Control "public, max-age=86400" always;
        expires 24h;
    }
    
    # Redirect SVG favicon requests to centralized location
    location ~ ^/static/img/favicon\.svg$ {
        return 301 /favicon.svg;
    }

    # ================================================================
    # AUTHENTICATION ENDPOINTS
    # ================================================================
    
    # Main page
    location = / {
        proxy_pass http://auth-service:80/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Login and Logout
    location /login {
        proxy_pass http://auth-service:80/login;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /logout {
        proxy_pass http://auth-service:80/logout;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Password recovery
    location /forgot-password {
        proxy_pass http://auth-service:80/forgot-password;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /reset-password {
        proxy_pass http://auth-service:80/reset-password;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /access-denied {
        proxy_pass http://auth-service:80/access-denied;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ================================================================
    # USER INTERFACE ENDPOINTS
    # ================================================================
    
    # Menu endpoint (accessible to all authenticated users)
    location /menu {
        proxy_pass http://auth-service:80/menu;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Admin menu
    location /admin-menu {
        proxy_pass http://auth-service:80/admin-menu;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # User profile
    location /profile {
        proxy_pass http://auth-service:80/profile;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # System settings (for admins)
    location /settings {
        proxy_pass http://auth-service:80/settings;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ================================================================
    # ADMIN PANEL ENDPOINTS
    # ================================================================
    
    # Service management
    location /services {
        proxy_pass http://auth-service:80/services;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Service-specific Excel import/export endpoints (HIGH PRIORITY)
    location /service/ {
        proxy_pass http://auth-service:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # User management
    location /users {
        proxy_pass http://auth-service:80/users;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # ================================================================
    # LOGS VIEWER (DOZZLE) - Admin Only (all containers)
    # ================================================================
    
    location /logs {
        # Admin-only access check with forward-proxy headers
        auth_request /verify-logs-auth;
        auth_request_set $dozzle_user $upstream_http_remote_user;
        auth_request_set $dozzle_email $upstream_http_remote_email;
        auth_request_set $dozzle_name $upstream_http_remote_name;
        auth_request_set $dozzle_filter $upstream_http_remote_filter;
        
        error_page 401 = @error401;
        error_page 403 = @error403_logs;
        
        # Dozzle web UI with WebSocket support
        proxy_pass http://gateway-dozzle:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Forward proxy headers for Dozzle
        proxy_set_header Remote-User $dozzle_user;
        proxy_set_header Remote-Email $dozzle_email;
        proxy_set_header Remote-Name $dozzle_name;
        proxy_set_header Remote-Filter $dozzle_filter;
        
        # Important for WebSocket
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_connect_timeout 75s;
        
        # Disable buffering for real-time logs
        proxy_buffering off;
        proxy_cache off;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    
    # Verify logs access (admin sees all, others see filtered)
    location = /verify-logs-auth {
        internal;
        proxy_pass http://auth-service:80/verify-logs-access;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Service-specific logs viewer
    location ~ ^/services/([^/]+)/logs(/.*)?$ {
        set $service_key $1;
        
        # Check access with service filter
        auth_request /verify-service-logs-auth;
        auth_request_set $dozzle_user $upstream_http_remote_user;
        auth_request_set $dozzle_email $upstream_http_remote_email;
        auth_request_set $dozzle_name $upstream_http_remote_name;
        auth_request_set $dozzle_filter $upstream_http_remote_filter;
        
        error_page 401 = @error401;
        error_page 403 = @error403_service_logs;
        
        # Rewrite to Dozzle base path
        rewrite ^/services/[^/]+/logs(/.*)?$ /logs$1 break;
        
        # Dozzle web UI with WebSocket support
        proxy_pass http://gateway-dozzle:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Forward proxy headers for Dozzle
        proxy_set_header Remote-User $dozzle_user;
        proxy_set_header Remote-Email $dozzle_email;
        proxy_set_header Remote-Name $dozzle_name;
        proxy_set_header Remote-Filter $dozzle_filter;
        
        # Important for WebSocket
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_connect_timeout 75s;
        
        # Disable buffering for real-time logs
        proxy_buffering off;
        proxy_cache off;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    
    # Verify service-specific logs access
    location = /verify-service-logs-auth {
        internal;
        proxy_pass http://auth-service:80/verify-logs-access?service=$service_key;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Error handler for service logs - redirect to service page
    location @error403_service_logs {
        return 302 /services/$service_key;
    }
    
    # Special error handler for logs - redirect to menu
    location @error403_logs {
        return 302 /menu;
    }
    
    # User existence check
    location /check-user-exists {
        proxy_pass http://auth-service:80/check-user-exists;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Role management
    location /roles {
        proxy_pass http://auth-service:80/roles;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Permission management
    location /permissions {
        proxy_pass http://auth-service:80/permissions;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Notification settings
    location /notification-settings {
        proxy_pass http://auth-service:80/notification-settings;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Migration management
    location /migration {
        proxy_pass http://auth-service:80/migration;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Document types
    location /document-types {
        proxy_pass http://auth-service:80/document-types;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Available services
    location /available-services {
        proxy_pass http://auth-service:80/available-services;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ================================================================
    # API ENDPOINTS
    # ================================================================
    
    # General API endpoints (high priority prefix)
    location ^~ /api/ {
        proxy_pass http://auth-service:80/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Specific API for documents
    location /api/profile/documents {
        proxy_pass http://auth-service:80/api/profile/documents;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ================================================================
    # STATIC FILES & ASSETS
    # ================================================================
    
    # Data files from auth-service
    location /data/ {
        proxy_pass http://auth-service:80/data/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Avatar endpoint (no caching for fresh images)
    location /avatar/ {
        proxy_pass http://auth-service:80/avatar/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }
    
    # Static CSS/JS files with caching
    location /static/ {
        proxy_pass http://auth-service:80/static/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_valid 200 1h;
        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
        add_header Cache-Control "public, max-age=3600" always;
        expires 1h;
    }

    # ================================================================
    # INTERNAL AUTH VERIFICATION
    # ================================================================
    
    # Special endpoint to verify permissions without redirection
    location = /verify {
        internal;
        proxy_pass http://auth-service:80/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Admin-only verification endpoint
    location = /verify-admin {
        internal;
        proxy_pass http://auth-service:80/verify-admin;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ================================================================
    # ERROR HANDLING
    # ================================================================
    
    # Redirect to auth service for login if not authenticated
    error_page 401 = @error401;
    location @error401 {
        return 302 /login?redirect=$request_uri;
    }
    
    # Handle forbidden errors
    error_page 403 = @error403;
    location @error403 {
        return 302 /access-denied?service=$request_uri;
    }
    
    # Handle 404 errors with custom page
    error_page 404 /404.html;
    location = /404.html {
        root /usr/share/nginx/html;
        internal;
    }
    
    # ================================================================
    # EXTERNAL SERVICES (outside gateway service discovery)
    # ================================================================

    # Apartment Finder — standalone analytics service
    location /finder/ {
        proxy_pass http://apartment-finder/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /finder;
    }

    # Apartment Finder static files
    location /finder/static/ {
        proxy_pass http://apartment-finder/static/;
        proxy_set_header Host $host;
        proxy_cache_valid 200 1h;
        add_header Cache-Control "public, max-age=3600" always;
        expires 1h;
    }

    # ================================================================
    # DYNAMIC SERVICE DISCOVERY (master file in dynamic/services.conf)
    # ================================================================
    # Include dynamic service discovery master config
    # This master file is auto-generated by auth-service and includes individual service configs
    # Each service gets its own file: dynamic/service-{service_key}.conf
    include /etc/nginx/conf.d/dynamic/services.conf;
}
