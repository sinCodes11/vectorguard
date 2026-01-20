#!/bin/bash

# VectorGuard Setup Script
# This script sets up the VectorGuard threat intelligence platform

set -e

echo "🛡️  VectorGuard Setup Script"
echo "=============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

print_status "Docker and Docker Compose are installed."

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    print_status "Creating .env file from template..."
    cp .env.example .env
    print_warning "Please edit .env file with your configuration before proceeding."
    print_warning "Especially set a strong SECRET_KEY for production."
    
    # Generate a random secret key
    SECRET_KEY=$(openssl rand -hex 32)
    # Use different sed syntax for macOS and Linux
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/your-secret-key-here-change-in-production/$SECRET_KEY/" .env
    else
        sed -i "s/your-secret-key-here-change-in-production/$SECRET_KEY/" .env
    fi
    print_status "Generated random SECRET_KEY."
else
    print_status ".env file already exists."
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p data/postgres
mkdir -p data/redis
mkdir -p data/chroma
mkdir -p logs

# Set proper permissions
chmod 755 data logs

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local health_check_url=$2
    local max_attempts=30
    local attempt=1
    
    print_status "Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s $health_check_url > /dev/null 2>&1; then
            print_status "$service_name is ready!"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts..."
        sleep 2
        ((attempt++))
    done
    
    print_error "$service_name failed to start within expected time."
    return 1
}

# Start services
print_status "Starting VectorGuard services..."
docker-compose up -d postgres redis

# Wait for database
print_status "Waiting for PostgreSQL to be ready..."
wait_for_service "PostgreSQL" "http://localhost:5432" || {
    print_error "PostgreSQL is not responding"
    exit 1
}

# Wait for Redis
print_status "Waiting for Redis to be ready..."
wait_for_service "Redis" "http://localhost:6379" || {
    print_error "Redis is not responding"
    exit 1
}

# Run database migrations
print_status "Running database migrations..."
docker-compose run --rm backend python -c "
from src.database.connection import init_db
init_db()
print('Database initialized successfully!')
"

# Start all services
print_status "Starting all services..."
docker-compose up -d

# Wait for API to be ready
print_status "Waiting for API to be ready..."
wait_for_service "API" "http://localhost:8000/health" || {
    print_error "API is not responding"
    exit 1
}

# Wait for frontend to be ready
print_status "Waiting for frontend to be ready..."
wait_for_service "Frontend" "http://localhost:3000" || {
    print_warning "Frontend might still be starting up..."
}

print_status "All services are starting up!"
echo ""
echo "🎉 VectorGuard is now running!"
echo ""
echo "📍 Service URLs:"
echo "   Frontend:     http://localhost:3000"
echo "   API:          http://localhost:8000"
echo "   API Docs:     http://localhost:8000/docs"
echo "   API Redoc:    http://localhost:8000/redoc"
echo ""
echo "📊 Monitoring:"
echo "   Check service status: docker-compose ps"
echo "   View logs:           docker-compose logs -f [service]"
echo ""
echo "🛠️  Management Commands:"
echo "   Stop all services:   docker-compose down"
echo "   Restart services:    docker-compose restart"
echo "   Update services:     docker-compose pull && docker-compose up -d"
echo ""

# Display useful information
print_status "First-time setup recommendations:"
echo "1. Visit http://localhost:8000/docs to explore the API"
echo "2. Trigger initial data ingestion:"
echo "   curl -X POST http://localhost:8000/api/ingestion/trigger/cve"
echo "   curl -X POST http://localhost:8000/api/ingestion/trigger/advisory"
echo "3. Check system health:"
echo "   curl http://localhost:8000/health"
echo ""

print_status "Setup completed successfully! 🚀"