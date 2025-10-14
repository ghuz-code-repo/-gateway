# ===================================================================
# GATEWAY & AUTH-SERVICE CORE CONFIGURATION
# ===================================================================
# This file contains the core gateway configuration including:
# - Authentication endpoints (login, logout, password recovery)
# - Admin panel (users, roles, permissions, services)
# - Common endpoints (menu, profile, static files)
# - Internal auth verification endpoint
# ===================================================================

server {
    listen 80;
    server_name analytics.gh.uz localhost;
    
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
        proxy_pass http://auth-service:8080/vite.svg;
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
        proxy_pass http://auth-service:8080$request_uri;
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
        proxy_pass http://auth-service:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Login and Logout
    location /login {
        proxy_pass http://auth-service:8080/login;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /logout {
        proxy_pass http://auth-service:8080/logout;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Password recovery
    location /forgot-password {
        proxy_pass http://auth-service:8080/forgot-password;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /reset-password {
        proxy_pass http://auth-service:8080/reset-password;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /access-denied {
        proxy_pass http://auth-service:8080/access-denied;
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
        proxy_pass http://auth-service:8080/menu;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Admin menu
    location /admin-menu {
        proxy_pass http://auth-service:8080/admin-menu;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # User profile
    location /profile {
        proxy_pass http://auth-service:8080/profile;
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
        proxy_pass http://auth-service:8080/services;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Service-specific Excel import/export endpoints (HIGH PRIORITY)
    location /service/ {
        proxy_pass http://auth-service:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # User management
    location /users {
        proxy_pass http://auth-service:8080/users;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # User existence check
    location /check-user-exists {
        proxy_pass http://auth-service:8080/check-user-exists;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Role management
    location /roles {
        proxy_pass http://auth-service:8080/roles;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Permission management
    location /permissions {
        proxy_pass http://auth-service:8080/permissions;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Notification settings
    location /notification-settings {
        proxy_pass http://auth-service:8080/notification-settings;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Migration management
    location /migration {
        proxy_pass http://auth-service:8080/migration;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Document types
    location /document-types {
        proxy_pass http://auth-service:8080/document-types;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Available services
    location /available-services {
        proxy_pass http://auth-service:8080/available-services;
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
        proxy_pass http://auth-service:8080/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Specific API for documents
    location /api/profile/documents {
        proxy_pass http://auth-service:8080/api/profile/documents;
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
        proxy_pass http://auth-service:8080/data/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Avatar endpoint (no caching for fresh images)
    location /avatar/ {
        proxy_pass http://auth-service:8080/avatar/;
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
        proxy_pass http://auth-service:8080/static/;
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
        proxy_pass http://auth-service:8080/verify;
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
    # LEGACY SERVICES (defined in legacy.inc)
    # DYNAMIC SERVICE DISCOVERY (master file in dynamic/services.conf)
    # ================================================================
    # Include legacy services configuration
    include /etc/nginx/conf.d/legacy.inc;
    
    # Include dynamic service discovery master config
    # This master file is auto-generated by auth-service and includes individual service configs
    # Each service gets its own file: dynamic/service-{service_key}.conf
    include /etc/nginx/conf.d/dynamic/services.conf;
}
