import os
import time
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from core import telemetry, firewall, chatops, ai_engine

app = FastAPI(
    title="GOYS ChatOps & AIOps Platform",
    description="Asistente Conversacional para Monitoreo de Red y Mitigación de Incidentes en Tiempo Real",
    version="1.0.0"
)

class ChatRequest(BaseModel):
    message: str

class BlockRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Mitigación solicitada por operador"

class UnblockRequest(BaseModel):
    ip: str

_last_ai_analysis_timestamp = 0.0
_is_analyzing = False
_active_alert = None
_last_analyzed_fingerprint = ""

@app.get("/api/status")
def get_status():
    ping_nginx = telemetry.ping_host("172.20.0.10")
    ping_attacker = telemetry.ping_host("172.20.0.99")
    traffic = telemetry.get_traffic_metrics(50000)
    blocked_count = len(firewall.list_rules())
    ai_status = ai_engine.check_ai_status()
    
    return {
        "status": "healthy",
        "nodes": {
            "nginx": ping_nginx,
            "attacker": ping_attacker
        },
        "traffic": traffic,
        "ai": ai_status,
        "active_firewall_rules": blocked_count
    }

@app.get("/api/logs")
def get_logs(limit: int = 100):
    return telemetry.parse_logs(limit)

@app.get("/api/firewall")
def get_firewall_rules():
    return firewall.list_rules()

@app.post("/api/firewall/block")
def apply_block(req: BlockRequest):
    global _active_alert
    result = firewall.block_ip(req.ip, req.reason or "Mitigación aprobada vía Human-in-the-Loop")
    _active_alert = None
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/api/firewall/unblock")
def remove_block(req: UnblockRequest):
    global _active_alert, _last_analyzed_fingerprint
    result = firewall.unblock_ip(req.ip)
    _active_alert = None
    _last_analyzed_fingerprint = ""
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/api/reset")
def reset_lab():
    global _active_alert, _last_ai_analysis_timestamp, _last_analyzed_fingerprint
    telemetry.clear_logs()
    for ip in list(firewall.BLOCKED_IPS.keys()):
        firewall.unblock_ip(ip)
    _active_alert = None
    _last_ai_analysis_timestamp = 0.0
    _last_analyzed_fingerprint = ""
    return {"success": True, "message": "Laboratorio reseteado. Logs en 0 y reglas de firewall restablecidas."}

@app.post("/api/chat")
def handle_chat(req: ChatRequest):
    response = chatops.process_command(req.message)
    return response

@app.get("/api/alerts")
def check_proactive_alerts():
    global _last_ai_analysis_timestamp, _is_analyzing, _active_alert, _last_analyzed_fingerprint

    recent_logs = telemetry.parse_logs(150)
    if not recent_logs:
        return {"has_alert": False}

    last_30 = recent_logs[-30:] if len(recent_logs) >= 30 else recent_logs
    recent_auth_errors = sum(1 for l in last_30 if l["status"] in [401, 403, 404])
    recent_200 = sum(1 for l in recent_logs if l["status"] == 200)

    from collections import Counter
    recent_ips = Counter([l["ip"] for l in recent_logs])
    if not recent_ips:
        return {"has_alert": False}
    detected_ip, recent_count = recent_ips.most_common(1)[0]

    # Si la IP principal ya está bloqueada en firewall, no emitir alerta
    if firewall.is_blocked(detected_ip):
        _active_alert = None
        return {"has_alert": False}

    is_suspicious = (recent_count >= 15 or recent_auth_errors >= 3)
    if not is_suspicious:
        return {"has_alert": False}

    now = time.time()
    is_scan = (recent_auth_errors >= 3)
    is_dos = (recent_200 >= 30 and not is_scan)
    attack_type = "scan" if is_scan else ("dos" if is_dos else "unknown")
    traffic_fingerprint = f"{detected_ip}:{attack_type}"
    fingerprint_changed = (traffic_fingerprint != _last_analyzed_fingerprint)
    cooldown_passed = (now - _last_ai_analysis_timestamp >= 4.0)

    if (fingerprint_changed and cooldown_passed and not _is_analyzing):
        _is_analyzing = True
        try:
            ai_res = ai_engine.analyze_traffic_with_ollama()
            _last_ai_analysis_timestamp = time.time()
            _last_analyzed_fingerprint = traffic_fingerprint

            # Extraemos la IP dinámicamente resuelta por la IA o la telemetría
            suggested_action = ai_res.get("suggested_action")
            target_ip = (suggested_action.get("ip") if suggested_action else detected_ip)

            # Si la IP resultante ya fue mitigada, omitir
            if firewall.is_blocked(target_ip):
                _active_alert = None
                return {"has_alert": False}

            _active_alert = {
                "has_alert": True,
                "ip": target_ip,
                "count": recent_count,
                "auth_errors": recent_auth_errors,
                "ollama_online": ai_res.get("ollama_online", False),
                "model": ai_res.get("model", "N/A"),
                "message": ai_res["reply"],
                "suggested_action": suggested_action or {
                    "type": "block",
                    "ip": target_ip,
                    "label": f"Aplicar política DROP para {target_ip}"
                }
            }
        finally:
            _is_analyzing = False

    if _active_alert:
        return _active_alert

    return {"has_alert": False}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "GOYS ChatOps API en funcionamiento."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
