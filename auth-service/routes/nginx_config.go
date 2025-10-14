package routes

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/template"
	"time"

	"auth-service/models"
)

// NginxConfigData holds data for nginx configuration template
type NginxConfigData struct {
	Services []models.ServiceInstance
}

// nginxConfigTemplate is the template for dynamically generated nginx config
const nginxConfigTemplate = `# AUTO-GENERATED SERVICE DISCOVERY CONFIG
# Generated at: {{.GeneratedAt}}
# DO NOT EDIT MANUALLY - Changes will be overwritten

{{range .Services}}
# Service: {{.ServiceKey}}
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
    
    # Strip the service prefix before proxying
    rewrite ^{{.ExternalPrefix}}/(.*) /$1 break;
    
    proxy_pass {{.InternalURL}};
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
    proxy_pass {{.InternalURL}}{{.HealthCheckPath}};
    proxy_set_header Host $host;
    access_log off;
}

{{end}}
`

// GenerateNginxConfig generates nginx configuration from registered services
func GenerateNginxConfig() (string, error) {
	// Get all active service instances
	instances, err := models.GetActiveServiceInstances()
	if err != nil {
		return "", fmt.Errorf("failed to fetch active services: %v", err)
	}

	// Parse template
	tmpl, err := template.New("nginx").Parse(nginxConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse nginx template: %v", err)
	}

	// Prepare data
	data := struct {
		Services    []models.ServiceInstance
		GeneratedAt string
	}{
		Services:    instances,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute nginx template: %v", err)
	}

	return buf.String(), nil
}

// WriteNginxConfig writes the generated config to file
func WriteNginxConfig(configPath string) error {
	config, err := GenerateNginxConfig()
	if err != nil {
		return err
	}

	// Write to file
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write nginx config: %v", err)
	}

	log.Printf("Generated nginx config at: %s", configPath)
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

// regenerateNginxConfig generates config and reloads nginx
func regenerateNginxConfig() error {
	// Get config path from environment or use default
	configPath := os.Getenv("NGINX_DYNAMIC_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/nginx/conf.d/dynamic/services.conf"
	}

	// Write config
	if err := WriteNginxConfig(configPath); err != nil {
		return fmt.Errorf("failed to write nginx config: %v", err)
	}

	// Get nginx container name from environment or use default
	nginxContainer := os.Getenv("NGINX_CONTAINER_NAME")
	if nginxContainer == "" {
		nginxContainer = "gateway-nginx-1"
	}

	// Reload nginx
	if err := ReloadNginx(nginxContainer); err != nil {
		return fmt.Errorf("failed to reload nginx: %v", err)
	}

	log.Println("Nginx configuration regenerated and reloaded successfully")
	return nil
}
