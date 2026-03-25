"""
FastAPI Backend for CHRONOS
Real-time alerts, WebSocket, REST API
"""

import os
import logging
import asyncio
import secrets
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Query,
    Header,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import redis
import json

from chronos.core.detection.alert import Alert, AlertSeverity
from chronos.core.analytics.temporal import TemporalAnalyzer
from chronos.core.analytics.graph import GraphDetector
from chronos.core.analytics.identity import IdentityDetector
from chronos.soar.actions.response_actions import SOARResponseEngine
from chronos.core.threat_intel.client import MISPClient, ThreatIntelOrchestrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_KEY = os.getenv("CHRONOS_API_KEY", "chronos-secret-key-change-in-production")

MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
MISP_ENABLED = os.getenv("MISP_ENABLED", "false").lower() == "true"

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


class AlertCreate(BaseModel):
    title: str
    description: str
    severity: str
    technique: str = ""
    ttp: str = ""
    indicators: List[str] = []
    hostname: str = ""
    user: str = ""
    destination_ip: str = ""


class AlertResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str
    technique: str
    ttp: str
    indicators: List[str]
    metadata: Dict[str, Any]
    timestamp: str
    hostname: str
    user: str


class ConnectionManager:
    """WebSocket connection manager."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_json(message)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)


manager = ConnectionManager()

redis_client = None
soar_engine = None
misp_client = None
threat_intel = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, soar_engine, misp_client, threat_intel

    try:
        redis_client = redis.Redis(host="redis", port=6379, decode_responses=True)
        redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning(f"Redis not available: {e}")
        redis_client = None

    soar_config = {
        "edr": {"provider": "wazuh", "api_url": "http://wazuh:55000", "api_key": ""},
        "firewall": {"provider": "iptables"},
        "notifications": {"method": "slack", "slack_webhook": ""},
    }
    soar_engine = SOARResponseEngine(soar_config)

    if MISP_ENABLED and MISP_URL and MISP_API_KEY:
        try:
            misp_client = MISPClient(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)
            if misp_client.test_connection():
                logger.info("MISP client initialized successfully")
            else:
                logger.warning("MISP connection test failed - check URL and API key")
                misp_client = None
        except Exception as e:
            logger.error(f"Failed to initialize MISP client: {e}")
            misp_client = None

    if misp_client or VT_API_KEY or ABUSEIPDB_API_KEY:
        try:
            threat_intel = ThreatIntelOrchestrator(
                misp_config={"url": MISP_URL, "api_key": MISP_API_KEY}
                if MISP_URL and MISP_API_KEY
                else None,
                virustotal_config={"api_key": VT_API_KEY} if VT_API_KEY else None,
                abuseipdb_config={"api_key": ABUSEIPDB_API_KEY}
                if ABUSEIPDB_API_KEY
                else None,
            )
            logger.info("Threat intel orchestrator initialized")
        except Exception as e:
            logger.error(f"Failed to initialize threat intel orchestrator: {e}")

    yield

    if redis_client:
        redis_client.close()


app = FastAPI(
    title="CHRONOS API",
    description="APT Detection Platform API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"name": "CHRONOS API", "version": "1.0.0", "status": "running"}


@app.get("/health")
async def health():
    redis_status = "connected" if redis_client else "disconnected"
    return {
        "status": "healthy",
        "redis": redis_status,
        "websocket_connections": len(manager.active_connections),
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("type") == "ping":
                await manager.send_personal_message({"type": "pong"}, websocket)
            elif message.get("type") == "subscribe":
                logger.info(f"Client subscribed to alerts")

    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/api/alerts", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
):
    """Get alerts with optional filtering."""
    if redis_client:
        try:
            keys = redis_client.keys("alert:*")
            alerts = []

            for key in keys[offset : offset + limit]:
                alert_data = redis_client.get(key)
                if alert_data:
                    alert = json.loads(alert_data)

                    if severity and alert.get("severity") != severity:
                        continue
                    if status and alert.get("status") != status:
                        continue

                    alerts.append(alert)

            return alerts

        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")

    return []


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    """Get single alert by ID."""
    if redis_client:
        alert_data = redis_client.get(f"alert:{alert_id}")
        if alert_data:
            return json.loads(alert_data)

    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/alerts", response_model=AlertResponse)
async def create_alert(alert: AlertCreate):
    """Create new alert with optional threat intelligence enrichment."""
    alert_obj = Alert(
        title=alert.title,
        description=alert.description,
        severity=AlertSeverity(alert.severity),
        technique=alert.technique,
        ttp=alert.ttp,
        indicators=alert.indicators,
        hostname=alert.hostname,
        user=alert.user,
        destination_ip=alert.destination_ip,
    )

    alert_dict = alert_obj.to_dict()

    if threat_intel and alert.indicators:
        enrichment = []
        for ioc in alert.indicators:
            results = threat_intel.enrich_indicator(ioc)
            if results:
                enrichment.append(
                    {
                        "ioc": ioc,
                        "results": [
                            {
                                "source": r.source,
                                "reputation": r.reputation,
                                "score": r.score,
                            }
                            for r in results
                        ],
                    }
                )

        if enrichment:
            alert_dict["metadata"]["threat_intel"] = enrichment
            alert_dict["metadata"]["enriched"] = True

            aggregated = threat_intel.get_aggregated_score(
                [r for e in enrichment for r in e.get("results", [])]
            )
            if (
                aggregated.get("reputation") in ["malicious", "suspicious"]
                and aggregated.get("score", 0) > 25
            ):
                if alert_dict["severity"] == "low":
                    alert_dict["severity"] = "medium"
                elif alert_dict["severity"] == "medium":
                    alert_dict["severity"] = "high"

    if redis_client:
        redis_client.set(f"alert:{alert_obj.id}", json.dumps(alert_dict), ex=604800)

        redis_client.lpush("alerts:recent", alert_obj.id)
        redis_client.ltrim("alerts:recent", 0, 9999)

    await manager.broadcast({"type": "alert:new", "data": alert_dict})

    return alert_dict


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    """Acknowledge an alert."""
    if redis_client:
        key = f"alert:{alert_id}"
        alert_data = redis_client.get(key)

        if alert_data:
            alert = json.loads(alert_data)
            alert["status"] = "investigating"
            redis_client.set(key, json.dumps(alert))

            return {"status": "acknowledged"}

    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/alerts/{alert_id}/respond")
async def respond_to_alert(
    alert_id: str, action: str = Query(...), target: str = Query(...)
):
    """Execute response action on alert."""
    if not soar_engine:
        raise HTTPException(status_code=503, detail="SOAR not available")

    result = soar_engine.execute_response(action, target)

    return {
        "action": action,
        "target": target,
        "status": result.status.value,
        "message": result.message,
    }


@app.get("/api/stats")
async def get_stats():
    """Get alert statistics."""
    if not redis_client:
        return {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "mttd": 0,
            "mttr": 0,
        }

    try:
        keys = redis_client.keys("alert:*")
        total = len(keys)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                sev = alert.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {"total": total, **severity_counts, "mttd": 0, "mttr": 0}

    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {"error": str(e)}


@app.get("/api/hosts")
async def get_hosts():
    """Get host risk scores from registered agents."""
    if not redis_client:
        return []

    try:
        keys = redis_client.keys("agent:*")
        hosts = []

        for key in keys:
            agent_data = redis_client.get(key)
            if agent_data:
                agent = json.loads(agent_data)
                alert_keys = redis_client.keys(f"alert:*:{agent.get('hostname', '')}")
                host_alerts = 0
                for ak in alert_keys:
                    alert_data = redis_client.get(ak)
                    if alert_data:
                        host_alerts += 1

                hosts.append(
                    {
                        "hostname": agent.get("hostname", "Unknown"),
                        "risk_score": 0,
                        "alerts": host_alerts,
                        "criticality": "medium",
                        "platform": agent.get("platform", "Unknown"),
                        "status": agent.get("status", "unknown"),
                    }
                )

        return hosts
    except Exception as e:
        logger.error(f"Error getting hosts: {e}")
        return []


@app.get("/api/mitre/coverage")
async def get_mitre_coverage():
    """Get MITRE ATT&CK coverage from detected techniques."""
    if not redis_client:
        return {"tactics": [], "overall": 0}

    try:
        keys = redis_client.keys("alert:*")
        detected_techniques = set()

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                technique = alert.get("technique", "")
                if technique:
                    detected_techniques.add(technique)

        mitre_tactics = {
            "TA0001": {
                "name": "Initial Access",
                "techniques": [
                    "T1189",
                    "T1190",
                    "T1133",
                    "T1200",
                    "T1566",
                    "T1047",
                    "T1195",
                    "T1195.001",
                    "T1195.002",
                    "T1195.003",
                ],
            },
            "TA0002": {
                "name": "Execution",
                "techniques": [
                    "T1053",
                    "T1055",
                    "T1059",
                    "T1072",
                    "T1064",
                    "T1151",
                    "TT1609",
                    "T1196",
                    "T1220",
                    "T1203",
                    "T1106",
                ],
            },
            "TA0003": {
                "name": "Persistence",
                "techniques": [
                    "T1098",
                    "T1168",
                    "T1050",
                    "T1060",
                    "T1174",
                    "T1067",
                    "T1103",
                    "T1137",
                    "T1132",
                    "T1197",
                    "T1098.001",
                    "T1098.002",
                    "T1098.003",
                    "T1548",
                ],
            },
            "TA0004": {
                "name": "Privilege Escalation",
                "techniques": [
                    "T1068",
                    "T1067",
                    "T1168",
                    "T1055",
                    "T1053",
                    "T1060",
                    "T1548",
                    "T1574",
                    "T1075",
                    "T1100",
                ],
            },
            "TA0005": {
                "name": "Defense Evasion",
                "techniques": [
                    "T1140",
                    "T1085",
                    "T1093",
                    "T1222",
                    "T1218",
                    "T1070",
                    "T1562",
                    "T1034",
                    "T1006",
                    "T1055",
                ],
            },
            "TA0006": {
                "name": "Credential Access",
                "techniques": [
                    "T1110",
                    "T1187",
                    "T1212",
                    "T1208",
                    "T1552",
                    "T1557",
                    "T1040",
                    "T1003",
                ],
            },
            "TA0007": {
                "name": "Discovery",
                "techniques": [
                    "T1010",
                    "T1217",
                    "T1087",
                    "T1033",
                    "T1016",
                    "T1018",
                    "T1046",
                    "T1134",
                ],
            },
            "TA0008": {
                "name": "Lateral Movement",
                "techniques": ["T1021", "T1072", "T1091", "T1210", "T1534", "T1550"],
            },
            "TA0009": {
                "name": "Collection",
                "techniques": ["T1005", "T1039", "T1074", "T1185", "T1114", "T1056"],
            },
            "TA0010": {
                "name": "Command and Control",
                "techniques": [
                    "T1071",
                    "T1090",
                    "T1105",
                    "T1104",
                    "T1573",
                    "T1008",
                    "T1102",
                ],
            },
            "TA0011": {
                "name": "Exfiltration",
                "techniques": ["T1041", "T1048", "T1567", "T1537", "T1040"],
            },
            "TA0012": {
                "name": "Impact",
                "techniques": ["T1486", "T1490", "T1489", "T1529", "T1531"],
            },
        }

        tactics_coverage = []
        total_detected = 0
        total_techniques = 0

        for tactic_id, tactic_info in mitre_tactics.items():
            techniques = tactic_info["techniques"]
            detected = sum(1 for t in techniques if t in detected_techniques)
            total = len(techniques)
            coverage = int((detected / total) * 100) if total > 0 else 0

            tactics_coverage.append(
                {
                    "name": tactic_info["name"],
                    "coverage": coverage,
                    "detected": detected,
                    "total": total,
                }
            )

            total_detected += detected
            total_techniques += total

        overall = (
            int((total_detected / total_techniques) * 100)
            if total_techniques > 0
            else 0
        )

        return {"tactics": tactics_coverage, "overall": overall}
    except Exception as e:
        logger.error(f"Error getting MITRE coverage: {e}")
        return {"tactics": [], "overall": 0}


@app.get("/api/analytics/timeline")
async def get_analytics_timeline(range: str = "30d"):
    """Get alert timeline data for analytics."""
    if not redis_client:
        return []

    try:
        keys = redis_client.keys("alert:*")
        timeline = {}

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                timestamp = alert.get("timestamp", "")
                if timestamp:
                    date_key = (
                        timestamp.split("T")[0] if "T" in timestamp else timestamp[:10]
                    )
                    if date_key not in timeline:
                        timeline[date_key] = {
                            "date": date_key,
                            "alerts": 0,
                            "resolved": 0,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                        }
                    timeline[date_key]["alerts"] += 1
                    severity = alert.get("severity", "")
                    if severity == "critical":
                        timeline[date_key]["critical"] += 1
                    elif severity == "high":
                        timeline[date_key]["high"] += 1
                    elif severity == "medium":
                        timeline[date_key]["medium"] += 1

        result = sorted(timeline.values(), key=lambda x: x["date"])[:30]
        return result
    except Exception as e:
        logger.error(f"Error getting timeline: {e}")
        return []


@app.get("/api/analytics/techniques")
async def get_analytics_techniques():
    """Get top attack techniques data."""
    if not redis_client:
        return []

    try:
        keys = redis_client.keys("alert:*")
        technique_counts = {}

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                technique = alert.get("technique", "Unknown")
                ttp = alert.get("ttp", "")
                name = f"{technique} - {ttp}" if ttp else technique
                technique_counts[name] = technique_counts.get(name, 0) + 1

        result = [
            {"name": k, "count": v}
            for k, v in sorted(technique_counts.items(), key=lambda x: -x[1])[:10]
        ]
        return result
    except Exception as e:
        logger.error(f"Error getting techniques: {e}")
        return []


@app.get("/api/analytics/response-time")
async def get_analytics_response_time():
    """Get response time analytics."""
    return []


@app.get("/api/analytics/attack-vectors")
async def get_analytics_attack_vectors():
    """Get attack vector analytics."""
    if not redis_client:
        return []

    try:
        keys = redis_client.keys("alert:*")
        vector_counts = {}

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                technique = alert.get("technique", "")

                if "phish" in technique.lower() or "social" in technique.lower():
                    vector = "Phishing"
                elif "malware" in technique.lower() or "virus" in technique.lower():
                    vector = "Malware"
                elif "brute" in technique.lower() or "credential" in technique.lower():
                    vector = "Brute Force"
                elif "insider" in technique.lower() or "privilege" in technique.lower():
                    vector = "Insider"
                elif "vuln" in technique.lower() or "exploit" in technique.lower():
                    vector = "Vulnerability"
                elif "lateral" in technique.lower() or "remote" in technique.lower():
                    vector = "Lateral Movement"
                else:
                    vector = "Other"

                vector_counts[vector] = vector_counts.get(vector, 0) + 1

        result = [
            {"vector": k, "count": v}
            for k, v in sorted(vector_counts.items(), key=lambda x: -x[1])
        ]
        return result
    except Exception as e:
        logger.error(f"Error getting attack vectors: {e}")
        return []


@app.get("/api/analytics/sources")
async def get_analytics_sources():
    """Get alert source distribution."""
    if not redis_client:
        return []

    try:
        keys = redis_client.keys("alert:*")
        source_counts = {
            "Network": 0,
            "Endpoint": 0,
            "Email": 0,
            "Cloud": 0,
            "Other": 0,
        }

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                metadata = alert.get("metadata", {})
                source = metadata.get("source", "Other")

                if "network" in source.lower():
                    source_counts["Network"] += 1
                elif "endpoint" in source.lower() or "host" in source.lower():
                    source_counts["Endpoint"] += 1
                elif "email" in source.lower():
                    source_counts["Email"] += 1
                elif "cloud" in source.lower():
                    source_counts["Cloud"] += 1
                else:
                    source_counts["Other"] += 1

        total = sum(source_counts.values())
        if total == 0:
            return []

        result = [
            {"name": k, "value": int((v / total) * 100)}
            for k, v in source_counts.items()
            if v > 0
        ]
        return result
    except Exception as e:
        logger.error(f"Error getting sources: {e}")
        return []


@app.get("/api/analytics/metrics")
async def get_analytics_metrics():
    """Get key analytics metrics."""
    if not redis_client:
        return {"totalAlerts": 0, "resolutionRate": 0, "avgMttd": 0, "avgMttr": 0}

    try:
        keys = redis_client.keys("alert:*")
        total = len(keys)
        resolved = 0

        for key in keys:
            alert_data = redis_client.get(key)
            if alert_data:
                alert = json.loads(alert_data)
                if alert.get("status") == "resolved":
                    resolved += 1

        resolution_rate = int((resolved / total) * 100) if total > 0 else 0

        return {
            "totalAlerts": total,
            "resolutionRate": resolution_rate,
            "avgMttd": 0,
            "avgMttr": 0,
        }
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return {"totalAlerts": 0, "resolutionRate": 0, "avgMttd": 0, "avgMttr": 0}


@app.get("/api/profile")
async def get_profile():
    """Get user profile."""
    return {
        "name": "",
        "email": "",
        "role": "",
        "department": "",
        "lastLogin": datetime.now().isoformat(),
        "timezone": "UTC",
    }


@app.get("/api/profile/activity")
async def get_profile_activity():
    """Get user activity log."""
    return []


@app.post("/api/hunting/query")
async def run_hunt_query(request: Dict[str, Any]):
    """Run a threat hunting query."""
    return {"results": []}


@app.get("/api/hunting/queries")
async def get_hunting_queries():
    """Get saved hunting queries."""
    if not redis_client:
        return []

    try:
        keys = redis_client.keys("hunt_query:*")
        queries = []

        for key in keys:
            query_data = redis_client.get(key)
            if query_data:
                queries.append(json.loads(query_data))

        return queries
    except Exception as e:
        logger.error(f"Error getting hunting queries: {e}")
        return []


@app.post("/api/hunting/queries")
async def save_hunting_query(request: Dict[str, Any]):
    """Save a hunting query."""
    if not redis_client:
        return {"status": "error", "message": "Redis not available"}

    try:
        query_id = f"hunt_query:{datetime.now().timestamp()}"
        query_data = {
            "id": query_id,
            "name": request.get("name", "Untitled Query"),
            "query": request.get("query", ""),
            "techniques": request.get("techniques", []),
            "created_at": datetime.now().isoformat(),
        }
        redis_client.set(query_id, json.dumps(query_data), ex=604800)
        return {"status": "saved", "id": query_id}
    except Exception as e:
        logger.error(f"Error saving query: {e}")
        return {"status": "error", "message": str(e)}


@app.post("/api/hunting/run")
async def run_hunt(hypothesis: str = Query(...)):
    """Run a threat hunt."""
    logger.info(f"Running hunt: {hypothesis}")

    findings = []
    if redis_client:
        try:
            keys = redis_client.keys("alert:*")
            for key in keys:
                alert_data = redis_client.get(key)
                if alert_data:
                    alert = json.loads(alert_data)
                    technique = alert.get("technique", "").lower()
                    if (
                        hypothesis.lower() in technique
                        or technique in hypothesis.lower()
                    ):
                        findings.append(alert)
        except Exception as e:
            logger.error(f"Error running hunt: {e}")

    return {
        "status": "completed",
        "hypothesis": hypothesis,
        "findings": len(findings),
        "alerts_generated": 0,
        "duration_seconds": 0,
    }


def verify_api_key(x_api_key: str = Header(...)) -> bool:
    """Verify the API key."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


@app.post("/api/v1/agents/register")
async def register_agent(
    agent_data: Dict[str, Any],
    x_api_key: str = Header(...),
):
    """Register a new endpoint agent."""
    verify_api_key(x_api_key)

    agent_id = agent_data.get("agent_id")
    hostname = agent_data.get("hostname")
    platform = agent_data.get("platform")
    tags = agent_data.get("tags", [])

    if redis_client:
        agent_info = {
            "agent_id": agent_id,
            "hostname": hostname,
            "platform": platform,
            "tags": tags,
            "registered_at": datetime.now().isoformat(),
            "status": "active",
        }
        redis_client.set(f"agent:{agent_id}", json.dumps(agent_info), ex=604800)
        logger.info(f"Registered agent: {hostname} ({agent_id})")

    return {"status": "registered", "agent_id": agent_id}


@app.post("/api/v1/events")
async def receive_events(
    payload: Dict[str, Any],
    x_api_key: str = Header(...),
):
    """Receive events from endpoint agents."""
    verify_api_key(x_api_key)

    agent_id = payload.get("agent_id")
    hostname = payload.get("hostname")
    events = payload.get("events", [])

    if redis_client and events:
        for event in events:
            event["agent_id"] = agent_id
            event["hostname"] = hostname
            event["received_at"] = datetime.now().isoformat()

            redis_client.lpush("events:recent", json.dumps(event))
            redis_client.ltrim("events:recent", 0, 9999)

        logger.info(f"Received {len(events)} events from {hostname}")

    return {"status": "received", "count": len(events)}


@app.get("/api/v1/agents")
async def list_agents(x_api_key: str = Header(...)):
    """List all registered agents."""
    verify_api_key(x_api_key)

    if not redis_client:
        return {"agents": []}

    keys = redis_client.keys("agent:*")
    agents = []

    for key in keys:
        agent_data = redis_client.get(key)
        if agent_data:
            agents.append(json.loads(agent_data))

    return {"agents": agents}


@app.get("/api/v1/events")
async def get_events(
    x_api_key: str = Header(...),
    limit: int = Query(100, le=1000),
):
    """Get recent events from agents."""
    verify_api_key(x_api_key)

    if not redis_client:
        return {"events": []}

    events = redis_client.lrange("events:recent", 0, limit - 1)
    return {"events": [json.loads(e) for e in events]}


@app.get("/api/config")
async def get_api_config():
    """Get public API configuration."""
    return {
        "api_key_required": True,
        "version": "1.0.0",
        "endpoints": {
            "agents": "/api/v1/agents",
            "events": "/api/v1/events",
            "alerts": "/api/alerts",
            "stats": "/api/stats",
        },
    }


@app.get("/api/v1/threat-intel/status")
async def threat_intel_status(x_api_key: str = Header(...)):
    """Check threat intelligence platform status."""
    verify_api_key(x_api_key)

    misp_connected = False
    if misp_client:
        try:
            misp_connected = misp_client.test_connection()
        except:
            pass

    return {
        "misp": {
            "enabled": misp_client is not None,
            "connected": misp_connected,
            "url": MISP_URL,
            "configured": bool(MISP_URL and MISP_API_KEY),
        },
        "virustotal": {"enabled": bool(VT_API_KEY), "configured": bool(VT_API_KEY)},
        "abuseipdb": {
            "enabled": bool(ABUSEIPDB_API_KEY),
            "configured": bool(ABUSEIPDB_API_KEY),
        },
    }


@app.post("/api/v1/threat-intel/lookup")
async def threat_intel_lookup(request: Dict[str, Any], x_api_key: str = Header(...)):
    """Look up an IOC in threat intelligence feeds."""
    verify_api_key(x_api_key)

    if not threat_intel:
        raise HTTPException(
            status_code=503,
            detail="Threat intelligence not available - check configuration",
        )

    ioc = request.get("indicator")
    ioc_type = request.get("type")

    if not ioc:
        raise HTTPException(status_code=400, detail="Indicator is required")

    results = threat_intel.enrich_indicator(ioc, ioc_type)
    aggregated = threat_intel.get_aggregated_score(results)

    alert_created = None
    if (
        aggregated.get("reputation") in ["malicious", "suspicious"]
        and aggregated.get("score", 0) > 25
    ):
        alert_data = AlertCreate(
            title=f"Threat Intelligence Match: {ioc}",
            description=f"Indicator found in threat intelligence with score {aggregated.get('score')}",
            severity="high"
            if aggregated.get("reputation") == "malicious"
            else "medium",
            technique="T1071.001",
            indicators=[ioc],
        )
        alert_response = await create_alert(alert_data)
        alert_created = alert_response.get("id") if alert_response else None
        logger.info(f"Created alert {alert_created} for IOC {ioc}")

    return {
        "indicator": ioc,
        "indicator_type": ioc_type or "auto-detected",
        "found": aggregated.get("reputation") != "unknown",
        "reputation": aggregated.get("reputation"),
        "score": aggregated.get("score"),
        "sources": aggregated.get("sources"),
        "alert_created": alert_created,
        "details": aggregated.get("details", []),
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/v1/threat-intel/enrich-alert/{alert_id}")
async def enrich_alert_with_threat_intel(alert_id: str, x_api_key: str = Header(...)):
    """Enrich an existing alert with threat intelligence."""
    verify_api_key(x_api_key)

    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel not available")

    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis not available")

    alert_data = redis_client.get(f"alert:{alert_id}")
    if not alert_data:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = json.loads(alert_data)

    indicators = alert.get("indicators", [])
    if not indicators:
        import re

        text = f"{alert.get('title', '')} {alert.get('description', '')}"
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        domain_matches = re.findall(
            r"\b[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\b", text
        )
        indicators = list(set(ip_matches + domain_matches))

    enrichment_results = []
    for ioc in indicators:
        results = threat_intel.enrich_indicator(ioc)
        if results:
            enrichment_results.append(
                {
                    "ioc": ioc,
                    "found": True,
                    "results": [
                        {
                            "source": r.source,
                            "reputation": r.reputation,
                            "score": r.score,
                        }
                        for r in results
                    ],
                }
            )

    if enrichment_results:
        alert["metadata"]["threat_intel_enrichment"] = enrichment_results
        alert["metadata"]["enriched_at"] = datetime.now().isoformat()

        if any(r["found"] for r in enrichment_results):
            if alert["severity"] == "low":
                alert["severity"] = "medium"
            elif alert["severity"] == "medium":
                alert["severity"] = "high"

        redis_client.set(f"alert:{alert_id}", json.dumps(alert))

    return {
        "alert_id": alert_id,
        "indicators_checked": len(indicators),
        "malicious_found": len(enrichment_results),
        "results": enrichment_results,
        "severity_updated": alert.get("severity"),
    }


@app.get("/api/v1/threat-intel/cache/stats")
async def threat_intel_cache_stats(x_api_key: str = Header(...)):
    """Get threat intelligence cache statistics."""
    verify_api_key(x_api_key)

    return {
        "misp_url": MISP_URL,
        "misp_enabled": misp_client is not None,
        "threat_intel_configured": threat_intel is not None,
    }


llm_orchestrator = None


def get_llm_orchestrator():
    global llm_orchestrator
    if llm_orchestrator is None:
        try:
            from chronos.core.llm.orchestrator import get_orchestrator

            llm_orchestrator = get_orchestrator()
        except ImportError as e:
            logger.warning(f"LLM module not available: {e}")
            return None
    return llm_orchestrator


class LLMAnalysisRequest(BaseModel):
    alert_data: Dict[str, Any]
    include_hunt_queries: bool = True


class LLMSummaryRequest(BaseModel):
    alerts: List[Dict[str, Any]]


@app.get("/api/v1/llm/status")
async def llm_status(x_api_key: str = Header(...)):
    """Get LLM integration status."""
    verify_api_key(x_api_key)
    orchestrator = get_llm_orchestrator()

    if orchestrator is None:
        return {
            "enabled": False,
            "available": False,
            "message": "LLM module not installed",
        }

    return {
        "enabled": orchestrator.is_enabled,
        "available": True,
        "stats": orchestrator.stats,
    }


@app.post("/api/v1/llm/analyze")
async def llm_analyze(request: LLMAnalysisRequest, x_api_key: str = Header(...)):
    """Analyze an alert using LLM."""
    verify_api_key(x_api_key)
    orchestrator = get_llm_orchestrator()

    if orchestrator is None:
        raise HTTPException(status_code=503, detail="LLM module not available")

    try:
        analysis = orchestrator.analyze_alert(request.alert_data)

        hunt_queries = []
        if request.include_hunt_queries:
            hunt_queries = orchestrator.suggest_hunt_queries(request.alert_data)

        return {
            "analysis": {
                "threat_type": analysis.threat_type,
                "confidence": analysis.confidence,
                "description": analysis.description,
                "mitre_tactics": analysis.mitre_tactics,
                "mitre_techniques": analysis.mitre_techniques,
                "severity": analysis.severity,
                "recommendations": analysis.recommendations,
            },
            "hunt_queries": hunt_queries,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"LLM analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/llm/summarize")
async def llm_summarize(request: LLMSummaryRequest, x_api_key: str = Header(...)):
    """Generate summary of alerts using LLM."""
    verify_api_key(x_api_key)
    orchestrator = get_llm_orchestrator()

    if orchestrator is None:
        raise HTTPException(status_code=503, detail="LLM module not available")

    try:
        summary = orchestrator.generate_summary(request.alerts)

        return {
            "summary": summary,
            "alert_count": len(request.alerts),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"LLM summary failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/llm/config")
async def llm_config(x_api_key: str = Header(...)):
    """Get LLM configuration (non-sensitive)."""
    verify_api_key(x_api_key)
    orchestrator = get_llm_orchestrator()

    if orchestrator is None:
        return {"configured": False}

    config = orchestrator.config
    return {
        "configured": bool(config.api_key),
        "provider": config.provider,
        "model": config.model,
        "api_url": config.api_url,
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
        "cache_enabled": config.cache_enabled,
        "rate_limit": {
            "requests": config.rate_limit_requests,
            "period": config.rate_limit_period,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
