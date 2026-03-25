#!/bin/bash
# setup_threat_intel.sh - Configure threat intelligence for Chronos

set -e

echo "========================================="
echo "CHRONOS Threat Intelligence Setup"
echo "========================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [ ! -f config/.env ]; then
    echo "Creating config/.env file..."
    if [ -f config/.env.example ]; then
        cp config/.env.example config/.env
    else
        touch config/.env
    fi
fi

echo ""
echo "Enter your MISP configuration:"
echo "---------------------------------"

read -p "MISP URL (e.g., https://misp.local): " MISP_URL
read -p "MISP API Key: " MISP_API_KEY
read -p "Verify SSL? (true/false) [false]: " MISP_VERIFY_SSL
MISP_VERIFY_SSL=${MISP_VERIFY_SSL:-false}

echo ""

if [ -n "$MISP_URL" ]; then
    sed -i "s|MISP_URL=.*|MISP_URL=$MISP_URL|g" config/.env 2>/dev/null || echo "MISP_URL=$MISP_URL" >> config/.env
fi

if [ -n "$MISP_API_KEY" ]; then
    sed -i "s|MISP_API_KEY=.*|MISP_API_KEY=$MISP_API_KEY|g" config/.env 2>/dev/null || echo "MISP_API_KEY=$MISP_API_KEY" >> config/.env
fi

sed -i "s|MISP_VERIFY_SSL=.*|MISP_VERIFY_SSL=$MISP_VERIFY_SSL|g" config/.env 2>/dev/null || echo "MISP_VERIFY_SSL=$MISP_VERIFY_SSL" >> config/.env
sed -i "s|MISP_ENABLED=.*|MISP_ENABLED=true|g" config/.env 2>/dev/null || echo "MISP_ENABLED=true" >> config/.env

echo "MISP configuration saved to config/.env"

echo ""
echo "Installing Python dependencies..."
pip install -q requests python-dotenv cachetools 2>/dev/null || true

echo ""
echo "========================================="
echo "Setup complete! Next steps:"
echo "========================================="
echo ""
echo "1. Rebuild the API container:"
echo "   docker-compose build chronos-api"
echo ""
echo "2. Restart services:"
echo "   docker-compose down"
echo "   docker-compose --profile default --profile visualization up -d"
echo ""
echo "3. Test with:"
echo "   curl -s http://localhost:8000/api/v1/threat-intel/status \\"
echo "     -H 'X-API-Key: chronos-secret-key-2024' | jq ."
echo ""
echo "4. Test IOC lookup:"
echo "   curl -s -X POST http://localhost:8000/api/v1/threat-intel/lookup \\"
echo "     -H 'X-API-Key: chronos-secret-key-2024' \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"indicator\": \"8.8.8.8\", \"type\": \"ip\"}' | jq ."
echo ""
echo "5. Check logs:"
echo "   docker logs chronos-api --tail 50"
echo "========================================="
