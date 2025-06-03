# Gateway System with Authentication and Reverse Proxy

This project provides a central gateway with authentication and reverse proxy capabilities for accessing multiple microservices. The system ensures that users can only access services they have permission for based on their roles.

## Features

- Central authentication system with role-based access control
- Reverse proxy to route requests to appropriate services
- Docker containerization for easy deployment
- Simple interface for managing users, roles, and permissions
- Sample service demonstration

## Architecture

The system consists of:

1. **Nginx Reverse Proxy**: Routes requests to appropriate services and enforces authentication
2. **Auth Service (Go)**: Handles user authentication and permission management
3. **Backend Services**: Individual microservices like the sample service

## Prerequisites

- Docker and Docker Compose
- Go 1.16+ (for development only)
- Git

## Getting Started

### Running the System

1. Clone the repository:
   ```
   git clone <repository-url>
   cd GOTOSERVER
   ```

2. Start the containers:
   ```
   docker-compose up --build
   ```

3. Access the gateway at [http://localhost](http://localhost)

4. Login with default admin credentials:
   - Username: `admin`
   - Password: `admin123`

### Default Configuration

- The system comes pre-configured with:
  - An admin user that has access to all services
  - A "sample" service accessible at [http://localhost/sample/](http://localhost/sample/)
  - A placeholder for "plan-fact" service that will be at [http://localhost/plan-fact/](http://localhost/plan-fact/)

## Adding a New Service

To add a new service to the gateway:

1. **Create your Go service**
   
   Create a new directory for your service:
   
   ```
   mkdir -p my-new-service
   cd my-new-service
   ```
   
   Create the main Go file:
   
   ```go
   package main
   
   import (
       "fmt"
       "log"
       "net/http"
   )
   
   func main() {
       http.HandleFunc("/", myHandler)
       
       log.Println("Starting my service")
       if err := http.ListenAndServe(":8082", nil); err != nil {
           log.Fatalf("Failed to start server: %v", err)
       }
   }
   
   func myHandler(w http.ResponseWriter, r *http.Request) {
       fmt.Fprintf(w, "<h1>My New Service</h1>")
   }
   ```

2. **Create a Dockerfile** for your service:
   
   ```Dockerfile
   FROM golang:1.21-alpine AS builder
   
   WORKDIR /app
   
   # Copy go module files
   COPY go.mod go.sum ./
   RUN go mod download
   
   # Copy source code
   COPY . .
   
   # Build the application
   RUN go build -o my-service .
   
   # Final stage
   FROM alpine:latest
   
   WORKDIR /root/
   
   # Copy the binary from builder
   COPY --from=builder /app/my-service .
   
   EXPOSE 8082
   
   CMD ["./my-service"]
   ```

3. **Create a docker-compose.yml file** for your service:
   
   ```yaml
   services:
     my-service:
       build: .
       container_name: my-service
       networks:
         - services_network

   networks:
     services_network:
       external: true
       name: services_network
   ```

4. **Update the Nginx configuration** to include your new service:
   
   Edit `nginx/conf/default.conf` and add:
   
   ```nginx
   # My new service
   location /my-service/ {
       auth_request /auth/verify;
       auth_request_set $auth_status $upstream_status;
       
       proxy_pass http://my-service:8082/;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
       proxy_set_header X-Original-URI $request_uri;
   }
   ```

5. **Add the service permission** to the auth database:
   
   Login to the admin panel [http://localhost/auth/admin/](http://localhost/auth/admin/) and:
   
   - Go to "Manage Permissions"
   - Add a new permission for your service named exactly the same as your service path (e.g., "my-service")

6. **Assign permission to roles**:
   
   - Go to "Manage Roles"
   - Edit the roles that should have access to your service
   - Add the new service permission to those roles

7. **Rebuild and restart** the containers:
   
   ```
   docker-compose down
   docker-compose up --build
   ```

Your new service will be accessible at [http://localhost/my-service/](http://localhost/my-service/) for users with appropriate permissions.

## Adding a New Role

To create a new role with specific permissions:

1. **Login** to the admin panel at [http://localhost/auth/admin/](http://localhost/auth/admin/)

2. **Navigate** to "Manage Roles"

3. **Create a new role**:
   - Enter a name for the role (e.g., "developer")
   - Enter a description
   - Select the services this role should have access to
   - Click "Create Role"

4. **Assign the role to users**:
   - Go to "Manage Users"
   - Create a new user or edit an existing user
   - Assign your new role to the user

## Security Considerations

For production deployment:

1. **Change default passwords**:
   - Change the admin password immediately after first login
   - Use strong passwords for all users

2. **Set JWT secret**:
   - Set a strong JWT secret in the `docker-compose.yml` for the auth-service:
     ```yaml
     environment:
       - JWT_SECRET=your-very-strong-secret-key
     ```

3. **Enable HTTPS**:
   - Configure SSL certificates in Nginx
   - Update the Nginx configuration to use SSL

4. **Use a persistent database**:
   - For production, consider using a proper database like PostgreSQL instead of SQLite

5. **Set up proper logging**:
   - Configure centralized logging for all services

## Deploying on Ubuntu 24.04

1. **Install Docker and Docker Compose**:
   ```
   sudo apt update
   sudo apt install -y docker.io docker-compose
   ```

2. **Clone the repository** and navigate to it:
   ```
   git clone <repository-url>
   cd GOTOSERVER
   ```

3. **Start the system**:
   ```
   sudo docker-compose up -d
   ```

4. **Enable the Docker service** to start on boot:
   ```
   sudo systemctl enable docker
   ```

## Troubleshooting

- **Service not accessible**: Check that the service has been added correctly to the Nginx configuration and that the permission has been created and assigned to your user's role
- **Authentication issues**: Check that the JWT_SECRET environment variable is consistent and that your cookies are not being blocked
- **Docker network issues**: Ensure all services are on the same network and can communicate with each other

## License

This project is licensed under the MIT License - see the LICENSE file for details.
