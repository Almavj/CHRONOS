#!/bin/bash

echo "========================================="
echo "🔍 CHRONOS SYSTEM VERIFICATION"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check service
check_service() {
    if docker ps | grep -q $1; then
        echo -e "${GREEN}✅ $2 is running${NC}"
        return 0
    else
        echo -e "${RED}❌ $2 is NOT running${NC}"
        return 1
    fi
}

# Function to check API endpoint
check_api() {
    if curl -s -o /dev/null -w "%{http_code}" $1 | grep -q "200\|401"; then
        echo -e "${GREEN}✅ $2 accessible${NC}"
        return 0
    else
        echo -e "${RED}❌ $2 NOT accessible${NC}"
        return 1
    fi
}

echo "📊 CONTAINER STATUS:"
echo "-------------------"

# Check core infrastructure
check_service "chronos-zookeeper" "Zookeeper"
check_service "chronos-kafka" "Kafka"
check_service "elasticsearch" "Elasticsearch"
check_service "chronos-neo4j" "Neo4j"
check_service "chronos-redis" "Redis"

# Check Chronos core
check_service "chronos-api" "Chronos API"
check_service "chronos-engine" "Chronos Engine"

# Check visualization
check_service "chronos-frontend" "Frontend"
check_service "chronos-grafana" "Grafana"
check_service "chronos-kibana" "Kibana"
check_service "chronos-kafka-ui" "Kafka UI"

# Check MISP
check_service "chronos-misp" "MISP"
check_service "chronos-misp-db" "MISP Database"
check_service "chronos-misp-redis" "MISP Redis"

echo ""
echo "🌐 SERVICE ACCESSIBILITY:"
echo "------------------------"

# Check API endpoints
check_api "http://localhost:8000/health" "Chronos API Health"
check_api "http://localhost:8000/api/alerts" "Chronos Alerts API"
check_api "http://localhost:80" "Frontend"
check_api "http://localhost:3000" "Grafana"
check_api "http://localhost:5601" "Kibana"
check_api "https://localhost:8443" "MISP"
check_api "http://localhost:19200" "Elasticsearch"
check_api "http://localhost:8080" "Kafka UI"
check_api "http://localhost:7474" "Neo4j Browser"

echo ""
echo "🧪 FUNCTIONAL TESTS:"
echo "-------------------"

# Test 1: ML Models
echo -n "ML Models: "
if [ -f "models/dga_classifier.pth" ] && [ -f "models/beaconing_lstm.pth" ]; then
    echo -e "${GREEN}✅ Models present${NC}"
else
    echo -e "${RED}❌ Models missing${NC}"
fi

# Test 2: Kafka Topics
echo -n "Kafka Topics: "
TOPICS=$(docker exec chronos-kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null)
if echo "$TOPICS" | grep -q "chronos-events"; then
    echo -e "${GREEN}✅ Topics created${NC}"
else
    echo -e "${YELLOW}⚠️ Topics not found - run: python scripts/init_kafka_topics.py${NC}"
fi

# Test 3: Elasticsearch Indices
echo -n "Elasticsearch Indices: "
INDICES=$(curl -s "http://localhost:19200/_cat/indices/chronos-*?h=index")
if [ -n "$INDICES" ]; then
    echo -e "${GREEN}✅ Indices exist${NC}"
else
    echo -e "${YELLOW}⚠️ No indices - run: python scripts/init_elasticsearch.py${NC}"
fi

# Test 4: Alert Creation
echo -n "Alert Creation: "
ALERT=$(curl -s -X POST "http://localhost:8000/api/alerts" \
  -H "X-API-Key: chronos-secret-key-2024" \
  -H "Content-Type: application/json" \
  -d '{"title":"Verification Test","description":"Testing system","severity":"low","hostname":"test"}' | jq -r '.id')
if [ -n "$ALERT" ] && [ "$ALERT" != "null" ]; then
    echo -e "${GREEN}✅ Alert created: $ALERT${NC}"
else
    echo -e "${RED}❌ Alert creation failed${NC}"
fi

# Test 5: MISP Integration
echo -n "MISP Connection: "
MISP_STATUS=$(curl -s -k "https://localhost:8443/events" \
  -H "Authorization: 4hgxrZ7NfTwOJLoFWSau0cqQ9EmsteUbCzvdXk6R" 2>/dev/null | jq '.')
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ MISP API working${NC}"
else
    echo -e "${RED}❌ MISP connection failed${NC}"
fi

# Test 6: Sysmon Collector (check if running)
echo -n "Sysmon Collector: "
if pgrep -f "python.*sysmon_collector" > /dev/null; then
    echo -e "${GREEN}✅ Running${NC}"
else
    echo -e "${YELLOW}⚠️ Not running (start manually if needed)${NC}"
fi

# Test 7: Zeek Logs
echo -n "Zeek Logs: "
if [ -d "/opt/zeek/logs/current" ]; then
    echo -e "${GREEN}✅ Zeek directory exists${NC}"
else
    echo -e "${YELLOW}⚠️ Zeek not configured${NC}"
fi

# Test 8: Neo4j Connection
echo -n "Neo4j Connection: "
NEO4J_TEST=$(docker exec chronos-neo4j cypher-shell -u neo4j -p chronos123 "RETURN 1" 2>/dev/null)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Connected${NC}"
else
    echo -e "${RED}❌ Connection failed${NC}"
fi

echo ""
echo "========================================="
echo "📈 SYSTEM SUMMARY"
echo "========================================="

# Get stats
TOTAL_ALERTS=$(curl -s "http://localhost:8000/api/stats" -H "X-API-Key: chronos-secret-key-2024" | jq '.total')
echo "Total Alerts: $TOTAL_ALERTS"

# Check Redis alerts
REDIS_ALERTS=$(docker exec chronos-redis redis-cli KEYS "alert:*" | wc -l)
echo "Redis Alerts: $REDIS_ALERTS"

# Check ML models
ML_COUNT=$(ls -1 models/*.{pth,pkl} 2>/dev/null | wc -l)
echo "ML Models: $ML_COUNT"

echo ""
echo "========================================="
echo "✅ Verification Complete!"
echo "========================================="
