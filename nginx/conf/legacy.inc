# ===================================================================
# LEGACY SERVICES CONFIGURATION
# ===================================================================
# This file contains configurations for existing services that haven't
# migrated to the new service discovery system yet.
# Each service will eventually be moved to its own config file or
# migrated to dynamic service discovery.
# ===================================================================

# ================================================================
# REFERAL SERVICE - MIGRATED TO SERVICE DISCOVERY
# ================================================================
# Referal service has been migrated to use service discovery.
# Configuration is now automatically generated in dynamic/services.conf
# 
# Migration completed: October 14, 2025
# Service key: referal
# Internal URL: http://referal:80
#
# Old manual configuration is commented below for reference:
#
# location /referal/static/ { ... }
# location ~ ^/referal(?!/static/.*) { ... }
#
# ================================================================
# CLIENT SERVICE
# ================================================================

location /client-service {
    proxy_pass http://client-service-service:80;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# ================================================================
# DISABLED SERVICES
# ================================================================
# These services are commented out but kept for reference

# # Update the plan-fact location
# location /plan-fact/ {
#     auth_request /verify;
#     auth_request_set $auth_status $upstream_status;
#     auth_request_set $auth_user_name $upstream_http_x_user_name;
#     auth_request_set $auth_user_id $upstream_http_x_user_id;
#     auth_request_set $auth_user_admin $upstream_http_x_user_admin;
#     auth_request_set $auth_user_full_name $upstream_http_x_user_full_name;
#     auth_request_set $auth_user_roles $upstream_http_x_user_roles;
    
#     proxy_pass http://plan-fact:80;
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#     proxy_set_header X-Original-URI $request_uri;
    
#     # Pass user information
#     proxy_set_header X-User-Name $auth_user_name;
#     proxy_set_header X-User-ID $auth_user_id;
#     proxy_set_header X-User-Admin $auth_user_admin;
#     proxy_set_header X-User-Full-Name $auth_user_full_name;
#     proxy_set_header X-User-Full-Name-Encoding "base64";
#     proxy_set_header X-User-Roles $auth_user_roles;

    
#     # Debug header
#     add_header X-Auth-Status $auth_status always;
# }

# location /call-center/ {
#     auth_request /verify;
#     auth_request_set $auth_status $upstream_status;
#     auth_request_set $auth_user_name $upstream_http_x_user_name;
#     auth_request_set $auth_user_id $upstream_http_x_user_id;
#     auth_request_set $auth_user_admin $upstream_http_x_user_admin;
#     auth_request_set $auth_user_full_name $upstream_http_x_user_full_name;
#     auth_request_set $auth_user_roles $upstream_http_x_user_roles;

#     proxy_pass http://call-center-service:80;
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#     proxy_set_header X-Original-URI $request_uri;
    
#     # Pass user information
#     proxy_set_header X-User-Name $auth_user_name;
#     proxy_set_header X-User-ID $auth_user_id;
#     proxy_set_header X-User-Admin $auth_user_admin;
#     proxy_set_header X-User-Full-Name $auth_user_full_name;
#     proxy_set_header X-User-Full-Name-Encoding "base64";
#     proxy_set_header X-User-Roles $auth_user_roles;

#     # Debug header
#     add_header X-Auth-Status $auth_status always;
# }

# # Update the discount-system location
# location /discount-system/ {
#     auth_request /verify;
#     auth_request_set $auth_status $upstream_status;
#     auth_request_set $auth_user_name $upstream_http_x_user_name;
#     auth_request_set $auth_user_id $upstream_http_x_user_id;
#     auth_request_set $auth_user_admin $upstream_http_x_user_admin;
#     auth_request_set $auth_user_full_name $upstream_http_x_user_full_name;
#     auth_request_set $auth_user_roles $upstream_http_x_user_roles;

#     proxy_pass http://discount-service:80;
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#     proxy_set_header X-Original-URI $request_uri;
    
#     # Pass user information
#     proxy_set_header X-User-Name $auth_user_name;
#     proxy_set_header X-User-ID $auth_user_id;
#     proxy_set_header X-User-Admin $auth_user_admin;
#     proxy_set_header X-User-Full-Name $auth_user_full_name;
#     proxy_set_header X-User-Full-Name-Encoding "base64";
#     proxy_set_header X-User-Roles $auth_user_roles;

#     # Debug header
#     add_header X-Auth-Status $auth_status always;
# }

# location /calculators/ {
#     auth_request /verify;
#     auth_request_set $auth_status $upstream_status;
#     auth_request_set $auth_user_name $upstream_http_x_user_name;
#     auth_request_set $auth_user_id $upstream_http_x_user_id;
#     auth_request_set $auth_user_admin $upstream_http_x_user_admin;
#     auth_request_set $auth_user_full_name $upstream_http_x_user_full_name;
#     auth_request_set $auth_user_roles $upstream_http_x_user_roles;

#     proxy_pass http://calculators-service:80;
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#     proxy_set_header X-Original-URI $request_uri;
    
#     # Pass user information
#     proxy_set_header X-User-Name $auth_user_name;
#     proxy_set_header X-User-ID $auth_user_id;
#     proxy_set_header X-User-Admin $auth_user_admin;
#     proxy_set_header X-User-Full-Name $auth_user_full_name;
#     proxy_set_header X-User-Full-Name-Encoding "base64";
#     proxy_set_header X-User-Roles $auth_user_roles;

#     # Debug header
#     add_header X-Auth-Status $auth_status always;
# }
