#!/usr/bin/env python3
"""
Enterprise Topology Intelligence - Quick Start
Development startup script
"""

import os
import sys
import subprocess
import platform

def check_prerequisites():
    """Check if prerequisites are met"""
    print("🔍 Checking prerequisites...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    
    print("✅ Python version OK")
    
    # Check if pip packages are installed
    try:
        import fastapi
        import neo4j
        import pydantic
        print("✅ Required packages found")
    except ImportError:
        print("⚠️ Installing required packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    return True

def start_infrastructure():
    """Start infrastructure services"""
    print("🐳 Starting infrastructure with Docker...")
    
    # Check if Docker is available
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Docker not found - please install Docker")
            return False
    except FileNotFoundError:
        print("❌ Docker not found - please install Docker")
        return False
    
    print("✅ Docker found")
    
    # Start infrastructure services
    services = ["neo4j", "redis"]
    for service in services:
        print(f"🚀 Starting {service}...")
        result = subprocess.run([
            "docker", "run", "-d",
            "--name", f"enterprise-{service}",
            "--rm",
            "-p", "7474:7474" if service == "neo4j" else "6379:6379",
            "-p", "7687:7687" if service == "neo4j" else "",
            "-e", "NEO4J_AUTH=neo4j/enterprise-topology" if service == "neo4j" else "",
            "neo4j:5.14" if service == "neo4j" else "redis:7.2-alpine"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ {service} started successfully")
        else:
            print(f"⚠️ {service} might already be running or failed to start")
    
    return True

def run_setup():
    """Run platform setup"""
    print("⚙️ Running platform setup...")
    
    # Wait for Neo4j to be ready
    print("⏳ Waiting for Neo4j to be ready...")
    import time
    time.sleep(10)
    
    # Run setup script
    try:
        result = subprocess.run([sys.executable, "scripts/setup.py"], check=True)
        print("✅ Platform setup completed")
        return True
    except subprocess.CalledProcessError:
        print("❌ Platform setup failed")
        return False

def start_application():
    """Start the application"""
    print("🚀 Starting Enterprise Topology Intelligence...")
    
    # Set environment variables
    os.environ["NEO4J_URI"] = "bolt://localhost:7687"
    os.environ["NEO4J_USER"] = "neo4j"
    os.environ["NEO4J_PASSWORD"] = "enterprise-topology"
    os.environ["REDIS_URL"] = "redis://localhost:6379"
    os.environ["ENVIRONMENT"] = "development"
    
    # Start the application
    try:
        subprocess.run([sys.executable, "src/main.py"])
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
        cleanup()

def cleanup():
    """Cleanup Docker containers"""
    print("🧹 Cleaning up...")
    containers = ["enterprise-neo4j", "enterprise-redis"]
    
    for container in containers:
        subprocess.run(["docker", "stop", container], capture_output=True)
        print(f"🛑 Stopped {container}")

def main():
    """Main startup sequence"""
    print("🏢 Enterprise Topology Intelligence - Quick Start")
    print("=" * 60)
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Start infrastructure
    if not start_infrastructure():
        sys.exit(1)
    
    # Run setup
    if not run_setup():
        print("⚠️ Setup failed, but you can try starting anyway...")
    
    # Start application
    start_application()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
        cleanup()
    except Exception as e:
        print(f"\n❌ Startup failed: {e}")
        cleanup()
        sys.exit(1)