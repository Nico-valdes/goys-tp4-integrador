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
_current_analyzing_ip = None
_active_alerts_by_ip = {}
_pending_alert_queue = []
_last_analyzed_total_requests = 0
_last_analyzed_by_ip = {}

@app.get("/api/status")
def get_status():
    ping_nginx = telemetry.ping_host("172.20.0.10")
    ping_gateway = telemetry.ping_host("172.20.0.1")
    traffic = telemetry.get_traffic_metrics(50000)
    
    # Enriquecer orígenes detectados con estado de firewall
    for item in traffic.get("top_ips", []):
        item["is_blocked"] = firewall.is_blocked(item["ip"])
        item["status"] = "BLOQUEADO" if item["is_blocked"] else "PERMITIDO"

    blocked_count = len(firewall.list_rules())
    ai_status = ai_engine.check_ai_status()
    
    return {
        "status": "healthy",
        "nodes": {
            "nginx": ping_nginx,
            "gateway": ping_gateway
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
    global _active_alerts_by_ip, _pending_alert_queue
    result = firewall.block_ip(req.ip, req.reason or "Mitigación aprobada vía Human-in-the-Loop")
    _active_alerts_by_ip.pop(req.ip, None)
    _pending_alert_queue = [a for a in _pending_alert_queue if a.get("ip") != req.ip]
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/api/firewall/unblock")
def remove_block(req: UnblockRequest):
    global _active_alerts_by_ip, _pending_alert_queue, _last_analyzed_total_requests, _last_analyzed_by_ip
    result = firewall.unblock_ip(req.ip)
    _active_alerts_by_ip.pop(req.ip, None)
    _pending_alert_queue = [a for a in _pending_alert_queue if a.get("ip") != req.ip]
    _last_analyzed_total_requests = 0
    _last_analyzed_by_ip.pop(req.ip, None)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/api/reset")
def reset_lab():
    global _active_alerts_by_ip, _pending_alert_queue, _last_ai_analysis_timestamp, _last_analyzed_total_requests, _last_analyzed_by_ip
    telemetry.clear_logs()
    firewall.flush_all_rules()
    _active_alerts_by_ip.clear()
    _pending_alert_queue.clear()
    _last_ai_analysis_timestamp = 0.0
    _last_analyzed_total_requests = 0
    _last_analyzed_by_ip.clear()
    return {"success": True, "message": "Laboratorio reseteado. Logs en 0 y reglas de firewall restablecidas."}

@app.post("/api/alerts/dismiss")
def dismiss_active_alert():
    global _active_alerts_by_ip, _pending_alert_queue
    _active_alerts_by_ip.clear()
    _pending_alert_queue.clear()
    return {"success": True, "message": "Alertas descartadas."}

@app.post("/api/chat")
def handle_chat(req: ChatRequest):
    response = chatops.process_command(req.message)
    return response

@app.get("/api/alerts")
def check_proactive_alerts():
    global _last_ai_analysis_timestamp, _is_analyzing, _current_analyzing_ip
    global _active_alerts_by_ip, _pending_alert_queue, _last_analyzed_total_requests, _last_analyzed_by_ip

    # 1. Limpiar alertas de IPs que ya hayan sido bloqueadas en el firewall
    for ip in list(_active_alerts_by_ip.keys()):
        if firewall.is_blocked(ip):
            del _active_alerts_by_ip[ip]

    # 2. Si hay una nueva alerta en cola pendiente de entrega al frontend, entregarla primero
    if _pending_alert_queue:
        next_alert = _pending_alert_queue.pop(0)
        return next_alert

    # 3. Si actualmente se está ejecutando una inferencia de IA, reportar estado activo
    if _is_analyzing:
        return {"has_alert": False, "is_analyzing": True, "analyzing_ip": _current_analyzing_ip or "tráfico anómalo"}

    recent_logs = telemetry.parse_logs(2000)
    if not recent_logs:
        if _active_alerts_by_ip:
            last_ip = list(_active_alerts_by_ip.keys())[-1]
            return _active_alerts_by_ip[last_ip]
        return {"has_alert": False}

    # Descartar tráfico de orígenes que ya están mitigados en el firewall de kernel
    unblocked_logs = [l for l in recent_logs if not firewall.is_blocked(l["ip"])]
    if not unblocked_logs:
        if _active_alerts_by_ip:
            last_ip = list(_active_alerts_by_ip.keys())[-1]
            return _active_alerts_by_ip[last_ip]
        return {"has_alert": False}

    # Evaluar actividad en la ventana reciente activa (últimas 300 peticiones)
    recent_active_window = unblocked_logs[-300:] if len(unblocked_logs) >= 300 else unblocked_logs
    if not recent_active_window:
        if _active_alerts_by_ip:
            last_ip = list(_active_alerts_by_ip.keys())[-1]
            return _active_alerts_by_ip[last_ip]
        return {"has_alert": False}

    from collections import Counter
    now = time.time()
    detected_ip = None
    is_suspicious = False
    recent_count = 0
    recent_auth_errors = 0

    # A. Buscar orígenes con errores de autenticación/escaneo pendientes de alertar
    error_ips = Counter([l["ip"] for l in recent_active_window if l["status"] in [401, 403, 404]])
    for ip, err_count in error_ips.most_common(5):
        if not firewall.is_blocked(ip) and ip not in _active_alerts_by_ip:
            if err_count >= 3:
                if now - _last_analyzed_by_ip.get(ip, 0.0) >= 20.0:
                    detected_ip = ip
                    ip_logs = [l for l in recent_active_window if l["ip"] == detected_ip]
                    recent_count = len(ip_logs)
                    recent_auth_errors = err_count
                    is_suspicious = True
                    break

    # B. Si no hay escaneos nuevos, buscar ráfagas DoS volumétricas o User-Agent bot pendientes de alertar
    if not is_suspicious:
        ip_counts = Counter([l["ip"] for l in recent_active_window])
        for ip, count in ip_counts.most_common(5):
            if not firewall.is_blocked(ip) and ip not in _active_alerts_by_ip:
                logs_for_ip = [l for l in recent_active_window if l["ip"] == ip]
                uas = " ".join([l.get("user_agent", "") for l in logs_for_ip]).lower()
                has_bot = any(b in uas for b in ["attackbot", "bot", "python", "curl", "dirbuster", "nikto", "sqlmap"])
                ratio = count / len(recent_active_window)

                if (has_bot and count >= 15) or (count >= 30 and ratio >= 0.40):
                    if now - _last_analyzed_by_ip.get(ip, 0.0) >= 20.0:
                        detected_ip = ip
                        recent_count = count
                        recent_auth_errors = sum(1 for l in logs_for_ip if l["status"] in [401, 403, 404])
                        is_suspicious = True
                        break

    if not is_suspicious or not detected_ip:
        if _active_alerts_by_ip:
            last_ip = list(_active_alerts_by_ip.keys())[-1]
            return _active_alerts_by_ip[last_ip]
        return {"has_alert": False}

    raw_logs = telemetry.read_raw_logs(100000)
    total_requests = len(raw_logs)

    new_traffic_arrived = (abs(total_requests - _last_analyzed_total_requests) >= 10)
    cooldown_passed = (now - _last_ai_analysis_timestamp >= 3.0)

    if (new_traffic_arrived and cooldown_passed and not _is_analyzing):
        _is_analyzing = True
        _current_analyzing_ip = detected_ip
        try:
            ai_res = ai_engine.analyze_traffic_with_ollama(target_ip=detected_ip)
            _last_ai_analysis_timestamp = time.time()
            _last_analyzed_total_requests = total_requests
            _last_analyzed_by_ip[detected_ip] = time.time()

            # Si Ollama está offline o la inferencia falló
            if not ai_res.get("ollama_online", False) or not ai_res.get("success", False):
                return {"has_alert": False}

            suggested_action = ai_res.get("suggested_action")
            target_ip = detected_ip
            if suggested_action and suggested_action.get("ip"):
                target_ip = suggested_action.get("ip")

            if firewall.is_blocked(target_ip):
                return {"has_alert": False}

            # Si Capa 1 determinó anomalía crítica pero el LLM omitió la sintaxis exacta del botón
            if not suggested_action and is_suspicious:
                suggested_action = {
                    "type": "block",
                    "ip": target_ip,
                    "label": f"Aplicar política DROP para {target_ip}"
                }

            alert_data = {
                "has_alert": True,
                "alert_id": f"{target_ip}_{total_requests}_{int(time.time() * 1000)}",
                "ip": target_ip,
                "count": recent_count,
                "auth_errors": recent_auth_errors,
                "ollama_online": True,
                "model": ai_res.get("model", "N/A"),
                "message": ai_res["reply"],
                "suggested_action": suggested_action
            }
            _active_alerts_by_ip[target_ip] = alert_data
            _pending_alert_queue.append(alert_data)
            return alert_data
        finally:
            _is_analyzing = False
            _current_analyzing_ip = None

    if _active_alerts_by_ip:
        last_ip = list(_active_alerts_by_ip.keys())[-1]
        return _active_alerts_by_ip[last_ip]

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
