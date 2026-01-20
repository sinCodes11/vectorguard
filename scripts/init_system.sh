#!/bin/bash

# VectorGuard System Initialization Script
# This script initializes the database and triggers initial data ingestion

set -e

echo "🚀 VectorGuard System Initialization"
echo "===================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found!${NC}"
    echo "Please copy .env.example to .env and configure it first."
    exit 1
fi

echo -e "${GREEN}✓${NC} Found .env file"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running!${NC}"
    echo "Please start Docker and try again."
    exit 1
fi

echo -e "${GREEN}✓${NC} Docker is running"

# Start services
echo ""
echo "Starting services..."
docker-compose up -d

# Wait for services to be ready
echo ""
echo "Waiting for services to be ready..."
sleep 10

# Check if backend is responding
echo ""
echo "Checking backend health..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Backend is healthy"
        break
    fi
    attempt=$((attempt + 1))
    echo "Waiting for backend... ($attempt/$max_attempts)"
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}Error: Backend failed to start${NC}"
    echo "Check logs with: docker-compose logs backend"
    exit 1
fi

# Trigger initial data ingestion
echo ""
echo "Triggering initial CVE data ingestion..."
curl -X POST http://localhost:8000/api/ingestion/trigger/cve \
    -H "Content-Type: application/json" \
    || echo -e "${YELLOW}Warning: CVE ingestion trigger failed${NC}"

echo ""
echo "Triggering initial advisory data ingestion..."
curl -X POST http://localhost:8000/api/ingestion/trigger/advisory \
    -H "Content-Type: application/json" \
    || echo -e "${YELLOW}Warning: Advisory ingestion trigger failed${NC}"

echo ""
echo -e "${GREEN}✓${NC} Initial data ingestion triggered"

# Display status
echo ""
echo "===================================="
echo -e "${GREEN}System Initialization Complete!${NC}"
echo "===================================="
echo ""
echo "Services:"
echo "  - Backend API: http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - Frontend: http://localhost:3000"
echo ""
echo "Default Admin Credentials:"
echo "  - Username: admin"
echo "  - Password: changeme123"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Change the default password immediately!${NC}"
echo ""
echo "Next steps:"
echo "  1. Visit http://localhost:8000/docs to explore the API"
echo "  2. Wait 5-10 minutes for initial data ingestion to complete"
echo "  3. Check ingestion status: curl http://localhost:8000/api/ingestion/stats"
echo "  4. Try a search: curl -X POST http://localhost:8000/api/search -H 'Content-Type: application/json' -d '{\"query\":\"remote code execution\",\"limit\":10}'"
echo ""
echo "View logs:"
echo "  - All services: docker-compose logs -f"
echo "  - Backend only: docker-compose logs -f backend"
echo "  - Celery worker: docker-compose logs -f celery-worker"
echo ""

