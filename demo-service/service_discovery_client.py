"""
Service Discovery Client for Python Microservices

This module provides automatic service registration and deregistration 
with the gateway's service discovery system.

Usage:
    from service_discovery import ServiceDiscoveryClient
    
    # Create client
    client = ServiceDiscoveryClient(
        service_key="my-service",
        internal_url="http://my-service:8080",
        registry_url="http://auth-service:8080/api/registry"
    )
    
    # Register on startup
    client.register()
    
    # Send periodic heartbeats
    client.start_heartbeat()
    
    # Deregister on shutdown
    client.deregister()
"""

import requests
import threading
import time
import logging
import atexit
import signal
import sys
import socket
from typing import Optional, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServiceDiscoveryClient:
    """Client for automatic service registration with gateway"""
    
    def __init__(
        self,
        service_key: str,
        internal_url: str,
        registry_url: str = "http://auth-service:8080/api/registry",
        container_name: Optional[str] = None,
        health_check_path: str = "/health",
        heartbeat_interval: int = 30,
        metadata: Optional[Dict[str, str]] = None
    ):
        """
        Initialize service discovery client
        
        Args:
            service_key: Unique key identifying the service (must exist in services collection)
            internal_url: Internal Docker network URL (e.g., "http://my-service:8080")
            registry_url: URL of the service registry API
            container_name: Docker container name (auto-detected if None)
            health_check_path: Path to health check endpoint
            heartbeat_interval: Seconds between heartbeat signals
            metadata: Additional service metadata
        """
        self.service_key = service_key
        self.internal_url = internal_url
        self.registry_url = registry_url
        self.container_name = container_name or self._get_container_name()
        self.health_check_path = health_check_path
        self.heartbeat_interval = heartbeat_interval
        self.metadata = metadata or {}
        
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()
        self._registered = False
        
        # Register cleanup handlers
        atexit.register(self.deregister)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _get_container_name(self) -> str:
        """Get container name from hostname"""
        return socket.gethostname()
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, deregistering service...")
        self.deregister()
        sys.exit(0)
    
    def register(self) -> bool:
        """
        Register service with the registry
        
        Returns:
            True if registration successful, False otherwise
        """
        try:
            payload = {
                "service_key": self.service_key,
                "container_name": self.container_name,
                "internal_url": self.internal_url,
                "health_check_path": self.health_check_path,
                "metadata": self.metadata
            }
            
            response = requests.post(
                f"{self.registry_url}/register",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self._registered = True
                logger.info(
                    f"✓ Service '{self.service_key}' registered successfully "
                    f"(container: {self.container_name}, url: {self.internal_url})"
                )
                return True
            else:
                logger.error(
                    f"✗ Failed to register service: {response.status_code} - {response.text}"
                )
                return False
                
        except Exception as e:
            logger.error(f"✗ Exception during registration: {e}")
            return False
    
    def deregister(self) -> bool:
        """
        Deregister service from the registry
        
        Returns:
            True if deregistration successful, False otherwise
        """
        if not self._registered:
            return True
        
        try:
            # Stop heartbeat first
            self.stop_heartbeat()
            
            response = requests.delete(
                f"{self.registry_url}/unregister/{self.service_key}",
                params={"container_name": self.container_name},
                timeout=10
            )
            
            if response.status_code == 200:
                self._registered = False
                logger.info(f"✓ Service '{self.service_key}' deregistered successfully")
                return True
            else:
                logger.error(
                    f"✗ Failed to deregister service: {response.status_code} - {response.text}"
                )
                return False
                
        except Exception as e:
            logger.error(f"✗ Exception during deregistration: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """
        Send heartbeat signal to registry
        
        Returns:
            True if heartbeat successful, False otherwise
        """
        try:
            payload = {
                "service_key": self.service_key,
                "container_name": self.container_name
            }
            
            response = requests.post(
                f"{self.registry_url}/heartbeat",
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.debug(f"Heartbeat sent for '{self.service_key}'")
                return True
            else:
                logger.warning(
                    f"Heartbeat failed: {response.status_code} - {response.text}"
                )
                return False
                
        except Exception as e:
            logger.warning(f"Heartbeat exception: {e}")
            return False
    
    def _heartbeat_loop(self):
        """Background thread for sending periodic heartbeats"""
        logger.info(f"Started heartbeat thread (interval: {self.heartbeat_interval}s)")
        
        while not self._stop_heartbeat.is_set():
            self.send_heartbeat()
            self._stop_heartbeat.wait(self.heartbeat_interval)
        
        logger.info("Heartbeat thread stopped")
    
    def start_heartbeat(self):
        """Start sending periodic heartbeats in background thread"""
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.warning("Heartbeat thread already running")
            return
        
        self._stop_heartbeat.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name=f"heartbeat-{self.service_key}"
        )
        self._heartbeat_thread.start()
    
    def stop_heartbeat(self):
        """Stop the heartbeat thread"""
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._stop_heartbeat.set()
            self._heartbeat_thread.join(timeout=5)


# Flask integration
def init_service_discovery_flask(app, service_key: str, internal_url: str, **kwargs):
    """
    Initialize service discovery for Flask application
    
    Example:
        from flask import Flask
        from service_discovery import init_service_discovery_flask
        
        app = Flask(__name__)
        init_service_discovery_flask(app, "my-service", "http://my-service:5000")
        
        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000)
    """
    client = ServiceDiscoveryClient(service_key, internal_url, **kwargs)
    
    # Flask 3.0+ compatible: use before_request with flag
    _registered = {'done': False}
    
    @app.before_request
    def register_service():
        if not _registered['done']:
            if client.register():
                client.start_heartbeat()
            _registered['done'] = True
    
    return client


# FastAPI integration
def init_service_discovery_fastapi(app, service_key: str, internal_url: str, **kwargs):
    """
    Initialize service discovery for FastAPI application
    
    Example:
        from fastapi import FastAPI
        from service_discovery import init_service_discovery_fastapi
        
        app = FastAPI()
        init_service_discovery_fastapi(app, "my-service", "http://my-service:8000")
        
        if __name__ == "__main__":
            import uvicorn
            uvicorn.run(app, host="0.0.0.0", port=8000)
    """
    client = ServiceDiscoveryClient(service_key, internal_url, **kwargs)
    
    @app.on_event("startup")
    async def register_service():
        if client.register():
            client.start_heartbeat()
    
    @app.on_event("shutdown")
    async def deregister_service():
        client.deregister()
    
    return client
