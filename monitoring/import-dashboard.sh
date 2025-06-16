#!/bin/bash

echo " Importing PEPCTL Dashboard to Grafana..."

# Wait for Grafana to be ready
echo "Waiting for Grafana to be ready..."
until curl -s http://localhost:3000/api/health >/dev/null 2>&1; do
echo "Waiting for Grafana..."
sleep 2
done

echo " Grafana is ready!"

# Import the dashboard
echo " Importing PEPCTL dashboard..."

curl -X POST \
-H "Content-Type: application/json" \
-d @grafana/provisioning/dashboards/pepctl-dashboard.json \
http://admin:pepctl123@localhost:3000/api/dashboards/db

echo ""
echo " Dashboard import completed!"
echo ""
echo " Access your dashboard at:"
echo " http://localhost:3000"
echo " Username: admin"
echo " Password: pepctl123"
echo ""
echo " Look for 'PEPCTL Network Policy Enforcement Dashboard'" 