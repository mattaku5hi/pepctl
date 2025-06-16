#!/bin/bash

echo "Setting up PEPCTL Monitoring Stack..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
echo "ERROR: Docker is not installed. Please install Docker first."
exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
echo "ERROR: Docker Compose is not installed. Please install Docker Compose first."
exit 1
fi

# Check if PEPCTL is running
if ! curl -s http://127.0.0.1:9090/health > /dev/null; then
echo "WARNING: PEPCTL daemon is not running on port 9090."
echo " Please start PEPCTL first with: sudo ./src/pepctl -c ../test_config.json -i lo --metrics-port 9090"
echo " Continuing anyway..."
fi

echo "Starting Prometheus and Grafana..."
docker-compose -f docker-compose.monitoring.yml up -d

echo "Waiting for services to start..."
sleep 10

echo "Monitoring stack is ready!"
echo ""
echo "Access URLs:"
echo " Prometheus: http://localhost:9091"
echo " Grafana: http://localhost:3000 (admin/pepctl123)"
echo " PEPCTL: http://localhost:9090/metrics"
echo ""
echo "To check status:"
echo " docker-compose -f docker-compose.monitoring.yml ps"
echo ""
echo "To stop:"
echo " docker-compose -f docker-compose.monitoring.yml down" 