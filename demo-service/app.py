"""
Demo Microservice with Automatic Service Discovery

This microservice automatically registers itself with the gateway
and demonstrates prefix-transparent operation.

When accessed via gateway:
  http://localhost/demo/hello  -> Proxied to this service's /hello

When accessed directly:
  http://demo-service:5000/hello -> Direct access

The service doesn't need to know about the /demo prefix!
"""

from flask import Flask, jsonify, request
import sys
import os

# Add parent directory to path to import service_discovery
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from service_discovery_client import init_service_discovery_flask

app = Flask(__name__)

# Initialize service discovery
# The service will automatically register as "demo" with the gateway
client = init_service_discovery_flask(
    app,
    service_key="demo",  # Must match a service in the services collection
    internal_url="http://demo-service:5000",
    health_check_path="/health",
    metadata={
        "version": "1.0.0",
        "description": "Demo service for service discovery"
    }
)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "demo",
        "version": "1.0.0"
    })


@app.route('/hello')
def hello():
    """Simple hello endpoint"""
    return jsonify({
        "message": "Hello from Demo Service!",
        "note": "This service doesn't know about the /demo prefix",
        "original_uri": request.headers.get('X-Original-URI', 'N/A'),
        "service_key": request.headers.get('X-Service-Key', 'N/A'),
        "service_prefix": request.headers.get('X-Service-Prefix', 'N/A')
    })


@app.route('/info')
def info():
    """Service information"""
    return jsonify({
        "service": "demo",
        "routes": [
            "/health",
            "/hello",
            "/info",
            "/echo"
        ],
        "registration": {
            "service_key": client.service_key,
            "container_name": client.container_name,
            "internal_url": client.internal_url,
            "registered": client._registered
        },
        "headers": dict(request.headers)
    })


@app.route('/echo', methods=['GET', 'POST'])
def echo():
    """Echo back request data"""
    return jsonify({
        "method": request.method,
        "path": request.path,
        "args": dict(request.args),
        "headers": dict(request.headers),
        "data": request.get_data(as_text=True) if request.data else None
    })


if __name__ == '__main__':
    print("="*60)
    print("Demo Service Starting")
    print("="*60)
    print(f"Service Key: {client.service_key}")
    print(f"Internal URL: {client.internal_url}")
    print(f"Container: {client.container_name}")
    print("="*60)
    print("\nAccess via gateway: http://localhost/demo/hello")
    print("Access directly: http://localhost:5001/hello")
    print("="*60)
    
    # Register service before starting Flask
    print("\nRegistering with service discovery...")
    if client.register():
        print("✓ Service registered successfully!")
        client.start_heartbeat()
        print("✓ Heartbeat started")
    else:
        print("✗ Failed to register service")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
