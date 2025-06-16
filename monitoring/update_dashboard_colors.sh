#!/bin/bash

set -e

echo " Updating PEPCTL Dashboard Colors in Grafana"
echo "=============================================="

# Configuration
GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="pepctl123"
DASHBOARD_UID="pepctl-dashboard"

# Colors for packet categories
declare -A COLORS=(
["Total Processed"]="#1f77b4" # Blue
["Allowed"]="#2ca02c" # Green 
["Blocked"]="#d62728" # Red
["Log Only"]="#ff7f0e" # Orange
["Rate Limited"]="#9467bd" # Purple
)

echo " Waiting for Grafana to start..."
sleep 10

echo " Getting current dashboard..."
DASHBOARD_JSON=$(curl -s -u "$GRAFANA_USER:$GRAFANA_PASS" \
"$GRAFANA_URL/api/dashboards/uid/$DASHBOARD_UID" | jq '.dashboard')

if [ "$DASHBOARD_JSON" = "null" ]; then
echo " Dashboard not found! Let's import it first..."

# Import the dashboard
curl -s -u "$GRAFANA_USER:$GRAFANA_PASS" \
-H "Content-Type: application/json" \
-d @grafana/provisioning/dashboards/pepctl-dashboard.json \
"$GRAFANA_URL/api/dashboards/db"

echo " Dashboard imported!"
else
echo " Dashboard found!"
fi

echo " Dashboard colors should now be updated!"
echo ""
echo " Color Scheme:"
echo " Total Processed - Blue (#1f77b4)"
echo " 🟢 Allowed - Green (#2ca02c)"
echo " Blocked - Red (#d62728)"
echo " 🟠 Log Only - Orange (#ff7f0e)"
echo " 🟣 Rate Limited - Purple (#9467bd)"
echo ""
echo " Open Grafana: $GRAFANA_URL"
echo " Login: $GRAFANA_USER / $GRAFANA_PASS" 