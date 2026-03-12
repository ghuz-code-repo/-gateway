package routes

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"auth-service/models"
)

// NginxConfigData holds data for nginx configuration template
type NginxConfigData struct {
	Services []models.ServiceInstance
}

// serviceConfigTemplate is the template for individual service nginx config
const serviceConfigTemplate = `# AUTO-GENERATED SERVICE CONFIG: {{.ServiceKey}}
# Generated at: {{.GeneratedAt}}
# DO NOT EDIT MANUALLY - Changes will be overwritten
#
# Service: {{.ServiceKey}}
# Internal URL: {{.InternalURL}}
# External Prefix: {{.ExternalPrefix}}
# Container: {{.ContainerName}}
# Status: {{.Status}}

# Static files for {{.ServiceKey}}
location {{.ExternalPrefix}}/static/ {
    proxy_pass {{.InternalURL}}/static/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Cache static files
    proxy_cache_valid 200 1h;
    proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
    add_header Cache-Control "public, max-age=3600" always;
    expires 1h;
}

location {{.ExternalPrefix}}/ {
    # Authentication
    auth_request /verify;
    auth_request_set $auth_status $upstream_status;
    auth_request_set $auth_user_name $upstream_http_x_user_name;
    auth_request_set $auth_user_id $upstream_http_x_user_id;
    auth_request_set $auth_user_admin $upstream_http_x_user_admin;
    auth_request_set $auth_user_roles $upstream_http_x_user_roles;
    auth_request_set $auth_user_permissions $upstream_http_x_user_permissions;
    auth_request_set $auth_user_service_roles $upstream_http_x_user_service_roles;
    auth_request_set $auth_user_service_permissions $upstream_http_x_user_service_permissions;
    auth_request_set $auth_user_full_name $upstream_http_x_user_full_name;
    auth_request_set $auth_user_full_name_encoding $upstream_http_x_user_full_name_encoding;
    auth_request_set $auth_user_avatar $upstream_http_x_user_avatar;
    auth_request_set $auth_user_email $upstream_http_x_user_email;
    auth_request_set $auth_user_phone $upstream_http_x_user_phone;
    
    # Use variable for dynamic DNS resolution
    # This allows nginx to start even if upstream is not available
    set $backend_{{.SafeServiceKey}} {{.InternalURL}};
    
    # Strip the service prefix before proxying
    rewrite ^{{.ExternalPrefix}}/(.*) /$1 break;
    
    proxy_pass $backend_{{.SafeServiceKey}};
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix {{.ExternalPrefix}};
    proxy_set_header X-Original-URI $request_uri;
    
    # Pass authentication information
    proxy_set_header X-User-Name $auth_user_name;
    proxy_set_header X-User-ID $auth_user_id;
    proxy_set_header X-User-Admin $auth_user_admin;
    proxy_set_header X-User-Roles $auth_user_roles;
    proxy_set_header X-User-Permissions $auth_user_permissions;
    proxy_set_header X-User-Service-Roles $auth_user_service_roles;
    proxy_set_header X-User-Service-Permissions $auth_user_service_permissions;
    proxy_set_header X-User-Full-Name $auth_user_full_name;
    proxy_set_header X-User-Full-Name-Encoding $auth_user_full_name_encoding;
    proxy_set_header X-User-Avatar $auth_user_avatar;
    proxy_set_header X-User-Email $auth_user_email;
    proxy_set_header X-User-Phone $auth_user_phone;
    
    # Add service identification headers
    proxy_set_header X-Service-Key {{.ServiceKey}};
    proxy_set_header X-Service-Prefix {{.ExternalPrefix}};
    
    # Timeout settings
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
    
    # Buffer settings
    proxy_buffering on;
    proxy_buffer_size 4k;
    proxy_buffers 8 4k;
    proxy_busy_buffers_size 8k;
}

# Health check endpoint for {{.ServiceKey}}
location = {{.ExternalPrefix}}{{.HealthCheckPath}} {
    set $backend_{{.SafeServiceKey}}_health {{.InternalURL}}{{.HealthCheckPath}};
    proxy_pass $backend_{{.SafeServiceKey}}_health;
    proxy_set_header Host $host;
    access_log off;
}
`

// masterConfigTemplate is the template for the master include file
const masterConfigTemplate = `# AUTO-GENERATED SERVICES MASTER CONFIG
# Generated at: {{.GeneratedAt}}
# DO NOT EDIT MANUALLY - Changes will be overwritten
#
# ARCHITECTURE:
# - Each active service has its own config file: service-{service_key}.conf
# - This file includes all active service configs
# - When a service stops or is deleted, its file is removed and this file is regenerated
# - Gateway (auth-service + admin panel) is always available regardless of this file
#
# Total active services: {{.ServiceCount}}

{{if .Services}}{{range .Services}}# Include config for service: {{.ServiceKey}}
include /etc/nginx/conf.d/dynamic/service-{{.ServiceKey}}.conf;

{{end}}{{else}}# No services registered yet.
# Services will appear here automatically when they:
# 1. Start up with auth-connector integration
# 2. Call POST /api/registry/register
# 3. Send periodic heartbeats to stay active
#
# Gateway functionality (login, admin panel, auth) remains fully operational.
{{end}}
`

// GenerateServiceConfig generates nginx configuration for a single service
func GenerateServiceConfig(instance models.ServiceInstance) (string, error) {
	// Parse template
	tmpl, err := template.New("service").Parse(serviceConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse service config template: %v", err)
	}

	// Prepare data
	// SafeServiceKey: Replace hyphens with underscores for nginx variable names
	safeKey := instance.ServiceKey
	safeKey = replaceHyphensWithUnderscores(safeKey)

	data := struct {
		models.ServiceInstance
		SafeServiceKey string
		GeneratedAt    string
	}{
		ServiceInstance: instance,
		SafeServiceKey:  safeKey,
		GeneratedAt:     time.Now().Format(time.RFC3339),
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute service config template: %v", err)
	}

	return buf.String(), nil
}

// replaceHyphensWithUnderscores replaces hyphens with underscores for nginx variable names
func replaceHyphensWithUnderscores(s string) string {
	return strings.ReplaceAll(s, "-", "_")
}

// GenerateMasterConfig generates the master include file for all active services
func GenerateMasterConfig(activeServices []models.ServiceInstance) (string, error) {
	// Parse template
	tmpl, err := template.New("master").Parse(masterConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse master config template: %v", err)
	}

	// Prepare data
	data := struct {
		Services     []models.ServiceInstance
		ServiceCount int
		GeneratedAt  string
	}{
		Services:     activeServices,
		ServiceCount: len(activeServices),
		GeneratedAt:  time.Now().Format(time.RFC3339),
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute master config template: %v", err)
	}

	return buf.String(), nil
}

// GetActiveServicesForNginx fetches all services that should have nginx routes.
// CRITICAL: This returns ALL registered services (not just those with a live heartbeat)
// to prevent nginx 404s when a service temporarily loses heartbeat or restarts.
// A service route should only be removed when the service is explicitly deleted.
func GetActiveServicesForNginx() ([]models.ServiceInstance, error) {
	// Get ALL non-deleted services from database
	services, err := models.GetAllServices()
	if err != nil {
		log.Printf("Warning: Could not fetch services from DB: %v. Using empty list.", err)
		return []models.ServiceInstance{}, nil
	}

	// Get service instances (any status) for their connection details
	allInstances, err := models.GetAllServiceInstances()
	if err != nil {
		log.Printf("Warning: Could not fetch service instances: %v", err)
		allInstances = []models.ServiceInstance{}
	}

	// Build instance map — prefer active, but keep any instance as fallback
	instancesMap := make(map[string]*models.ServiceInstance)
	for i := range allInstances {
		existing, exists := instancesMap[allInstances[i].ServiceKey]
		if !exists || existing.Status != "active" {
			instancesMap[allInstances[i].ServiceKey] = &allInstances[i]
		}
	}

	// Build nginx routes for ALL non-deleted services that have ever registered
	var nginxServices []models.ServiceInstance
	for _, service := range services {
		if service.Status == "deleted" {
			continue
		}

		if instance, hasInstance := instancesMap[service.Key]; hasInstance {
			// Use registered instance details (internal URL, health path, etc.)
			nginxServices = append(nginxServices, *instance)
		}
		// If no instance ever registered, we can't create a route (no internal URL known)
	}

	return nginxServices, nil
}

// WriteServiceConfig writes individual service config file
func WriteServiceConfig(baseDir string, instance models.ServiceInstance) error {
	config, err := GenerateServiceConfig(instance)
	if err != nil {
		return err
	}

	// Create filename: service-{service_key}.conf
	filename := fmt.Sprintf("service-%s.conf", instance.ServiceKey)
	fullPath := filepath.Join(baseDir, filename)

	// Write to file
	if err := os.WriteFile(fullPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write service config: %v", err)
	}

	log.Printf("Generated service config for '%s' at: %s", instance.ServiceKey, fullPath)
	return nil
}

// DeleteServiceConfig removes individual service config file
func DeleteServiceConfig(baseDir string, serviceKey string) error {
	filename := fmt.Sprintf("service-%s.conf", serviceKey)
	fullPath := filepath.Join(baseDir, filename)

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// File doesn't exist - not an error
		log.Printf("Service config for '%s' does not exist (already deleted)", serviceKey)
		return nil
	}

	// Delete the file
	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to delete service config: %v", err)
	}

	log.Printf("Deleted service config for '%s' at: %s", serviceKey, fullPath)
	return nil
}

// WriteMasterConfig writes the master include file
func WriteMasterConfig(configPath string, activeServices []models.ServiceInstance) error {
	config, err := GenerateMasterConfig(activeServices)
	if err != nil {
		return err
	}

	// Write to file
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write master config: %v", err)
	}

	log.Printf("Generated master config at: %s (includes %d services)", configPath, len(activeServices))
	return nil
}

// ReloadNginx safely reloads nginx configuration
func ReloadNginx(containerName string) error {
	// First, test the configuration
	testCmd := exec.Command("docker", "exec", containerName, "nginx", "-t")
	output, err := testCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx config test failed: %v\nOutput: %s", err, string(output))
	}

	log.Printf("Nginx config test passed: %s", string(output))

	// Reload nginx gracefully
	reloadCmd := exec.Command("docker", "exec", containerName, "nginx", "-s", "reload")
	output, err = reloadCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx reload failed: %v\nOutput: %s", err, string(output))
	}

	log.Printf("Nginx reloaded successfully: %s", string(output))
	return nil
}

// InitializeNginxConfig creates an initial nginx config if it doesn't exist
// This ensures nginx can start even without any registered services
func InitializeNginxConfig() error {
	configDir := os.Getenv("NGINX_DYNAMIC_CONFIG_DIR")
	if configDir == "" {
		configDir = "/etc/nginx/conf.d/dynamic"
	}

	masterConfigPath := filepath.Join(configDir, "services.conf")

	// Check if config already exists
	if _, err := os.Stat(masterConfigPath); err == nil {
		log.Printf("Nginx master config already exists at: %s", masterConfigPath)
		return nil
	}

	// Create initial empty config
	log.Printf("Creating initial nginx config at: %s", masterConfigPath)

	// Get active services (should be empty on first run)
	activeServices, err := GetActiveServicesForNginx()
	if err != nil {
		log.Printf("Warning: Failed to get active services during init: %v", err)
		activeServices = []models.ServiceInstance{}
	}

	return WriteMasterConfig(masterConfigPath, activeServices)
}

// regenerateNginxConfig regenerates all configs and reloads nginx
func regenerateNginxConfig() error {
	// Get config directory from environment or use default
	configDir := os.Getenv("NGINX_DYNAMIC_CONFIG_DIR")
	if configDir == "" {
		configDir = "/etc/nginx/conf.d/dynamic"
	}

	// Master config path
	masterConfigPath := filepath.Join(configDir, "services.conf")

	// Get all active services
	activeServices, err := GetActiveServicesForNginx()
	if err != nil {
		log.Printf("Warning: Failed to get active services: %v", err)
		return nil
	}

	// Remove old service config files
	// Read directory and delete all service-*.conf files
	entries, err := os.ReadDir(configDir)
	if err != nil {
		log.Printf("Warning: Failed to read config directory: %v", err)
	} else {
		for _, entry := range entries {
			if !entry.IsDir() && entry.Name() != "services.conf" && filepath.Ext(entry.Name()) == ".conf" {
				oldPath := filepath.Join(configDir, entry.Name())
				if err := os.Remove(oldPath); err != nil {
					log.Printf("Warning: Failed to remove old config %s: %v", entry.Name(), err)
				}
			}
		}
	}

	// Write individual service configs
	for _, service := range activeServices {
		if err := WriteServiceConfig(configDir, service); err != nil {
			log.Printf("Warning: Failed to write config for service '%s': %v", service.ServiceKey, err)
		}
	}

	// Write master config
	if err := WriteMasterConfig(masterConfigPath, activeServices); err != nil {
		log.Printf("Warning: Failed to write master config: %v", err)
		return nil
	}

	// Get nginx container name from environment or use default
	nginxContainer := os.Getenv("NGINX_CONTAINER_NAME")
	if nginxContainer == "" {
		nginxContainer = "gateway-nginx-1"
	}

	// Reload nginx
	if err := ReloadNginx(nginxContainer); err != nil {
		log.Printf("Warning: Failed to reload nginx: %v", err)
		return nil
	}

	log.Println("Nginx configuration regenerated and reloaded successfully")
	return nil
}
