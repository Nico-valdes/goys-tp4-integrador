import os
import re
import time
import subprocess
from collections import Counter
from datetime import datetime

LOG_PATHS = [
    "/var/log/nginx/access.log",
    os.path.join(os.path.dirname(__file__), "../../nginx/logs/access.log"),
    os.path.join(os.getcwd(), "demo/nginx/logs/access.log"),
    os.path.join(os.getcwd(), "nginx/logs/access.log")
]

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"( rt=(?P<rt>\S+))?'
)

_last_request_count = 0
_last_check_timestamp = time.time()
_last_rps = 0.0

def find_log_file() -> str:
    for path in LOG_PATHS:
        if os.path.exists(path):
            return path
    return LOG_PATHS[0]

def clear_logs() -> bool:
    global _last_request_count, _last_check_timestamp, _last_rps
    log_file = find_log_file()
    try:
        if os.path.exists(log_file):
            with open(log_file, "r+", encoding="utf-8") as f:
                f.truncate(0)
        _last_request_count = 0
        _last_check_timestamp = time.time()
        _last_rps = 0.0
        return True
    except Exception:
        try:
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("")
            return True
        except Exception:
            return False

def read_raw_logs(max_lines: int = 100000) -> list:
    log_file = find_log_file()
    if not os.path.exists(log_file):
        return []
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            return [line.strip() for line in lines[-max_lines:] if line.strip()]
    except Exception:
        return []

def parse_logs(max_lines: int = 100000) -> list:
    raw_lines = read_raw_logs(max_lines)
    parsed = []
    
    for line in raw_lines:
        match = LOG_PATTERN.match(line)
        if match:
            data = match.groupdict()
            parsed.append({
                "ip": data.get("ip"),
                "time": data.get("time"),
                "request": data.get("request"),
                "status": int(data.get("status", 0)),
                "bytes": int(data.get("bytes", 0)),
                "user_agent": data.get("user_agent", ""),
                "response_time": float(data.get("rt") or 0.0)
            })
        else:
            parts = line.split(" ")
            if len(parts) >= 7:
                parsed.append({
                    "ip": parts[0],
                    "time": datetime.now().strftime("%d/%b/%Y:%H:%M:%S"),
                    "request": f"{parts[5]} {parts[6]}" if len(parts) > 6 else parts[5],
                    "status": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 200,
                    "bytes": 0,
                    "user_agent": "Standard/Log",
                    "response_time": 0.0
                })
    return parsed

def get_traffic_metrics(window_lines: int = 100000) -> dict:
    global _last_request_count, _last_check_timestamp, _last_rps
    
    logs = parse_logs(window_lines)
    total_requests = len(logs)
    
    now = time.time()
    elapsed = max(now - _last_check_timestamp, 0.5)
    delta_requests = max(total_requests - _last_request_count, 0)
    current_rps = round(delta_requests / elapsed, 1)
    
    _last_request_count = total_requests
    _last_check_timestamp = now
    _last_rps = current_rps

    status_counts = Counter([entry["status"] for entry in logs])
    ip_counts = Counter([entry["ip"] for entry in logs])
    
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(5)]
    anomalous_ips = [ip for ip, count in ip_counts.items() if count >= 20]
    
    return {
        "total_requests": total_requests,
        "delta_requests": delta_requests,
        "rps": current_rps,
        "status_distribution": {
            "200_ok": status_counts.get(200, 0),
            "401_unauthorized": status_counts.get(401, 0),
            "403_forbidden": status_counts.get(403, 0),
            "404_not_found": status_counts.get(404, 0),
            "50x_server_error": sum(v for k, v in status_counts.items() if 500 <= k < 600)
        },
        "top_ips": top_ips,
        "suspect_ips": anomalous_ips,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def generate_telemetry_digest(window_lines: int = 150) -> dict:
    """
    Arquitectura en Dos Capas (Two-Tier AIOps):
    Analiza la ventana de observación activa (ráfaga reciente) distinguiendo
    entre escaneo activo / fuerza bruta y ataques volumétricos DoS,
    reportando métricas agregadas al LLM para inferencia precisa en milisegundos.
    """
    all_logs = parse_logs(100000)
    total_accumulated = len(all_logs)
    if total_accumulated == 0:
        return {
            "total_requests": 0,
            "recent_window_requests": 0,
            "top_ip": "127.0.0.1",
            "top_ip_count": 0,
            "concentration_pct": 0,
            "status_distribution": {"200_ok": 0, "auth_errors_401_403": 0, "not_found_404": 0},
            "top_user_agents": [],
            "sensitive_paths_targeted": []
        }

    # Identificar la naturaleza de la actividad reciente examinando los últimos 30 eventos
    last_30 = all_logs[-30:] if total_accumulated >= 30 else all_logs
    last_30_errors = sum(1 for l in last_30 if l["status"] in [401, 403, 404])

    if last_30_errors >= 3:
        # La ráfaga activa es de escaneo / autenticación fallida
        active_logs = [l for l in last_30 if l["status"] in [401, 403, 404] or any(k in l["request"].lower() for k in ["admin", ".env", "backup", "secret", "login", "sql"])]
        if not active_logs:
            active_logs = last_30
    else:
        # La ráfaga activa es volumétrica (DoS) o navegación continua
        active_logs = all_logs[-150:] if total_accumulated > 150 else all_logs

    recent_total = len(active_logs)
    ip_counter = Counter([l["ip"] for l in active_logs])
    status_counter = Counter([l["status"] for l in active_logs])
    ua_counter = Counter([l["user_agent"] for l in active_logs])
    path_counter = Counter([l["request"] for l in active_logs])

    top_ip, top_ip_count = ip_counter.most_common(1)[0]
    concentration_pct = round((top_ip_count / recent_total) * 100, 1)

    auth_errors = status_counter.get(401, 0) + status_counter.get(403, 0)
    not_found = status_counter.get(404, 0)

    # Rutas críticas detectadas en la ventana reciente
    sensitive_keywords = ["admin", ".env", "backup", "secret", "login", "sql"]
    sensitive_paths = [
        path for path, _ in path_counter.most_common(10)
        if any(k in path.lower() for k in sensitive_keywords)
    ]

    # Top User-Agents en la ventana reciente
    top_uas = [f"{ua} ({cnt}x)" for ua, cnt in ua_counter.most_common(3)]

    # Muestra de eventos de la ráfaga activa
    samples = [
        f"{l['ip']} - \"{l['request']}\" {l['status']} UA: \"{l['user_agent']}\""
        for l in active_logs[-3:]
    ]

    return {
        "total_requests": total_accumulated,
        "recent_window_requests": recent_total,
        "top_ip": top_ip,
        "top_ip_count": top_ip_count,
        "concentration_pct": concentration_pct,
        "status_distribution": {
            "200_ok": status_counter.get(200, 0),
            "auth_errors_401_403": auth_errors,
            "not_found_404": not_found
        },
        "top_user_agents": top_uas,
        "sensitive_paths_targeted": sensitive_paths,
        "samples": samples
    }

def ping_host(host_ip: str) -> dict:
    flag = "-n" if os.name == "nt" else "-c"
    timeout_flag = "-w" if os.name == "nt" else "-W"
    
    cmd = ["ping", flag, "1", timeout_flag, "1000", host_ip]
    start = time.time()
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        elapsed = round((time.time() - start) * 1000, 2)
        is_alive = result.returncode == 0
        return {
            "ip": host_ip,
            "alive": is_alive,
            "latency_ms": elapsed if is_alive else None,
            "status": "ONLINE" if is_alive else "UNREACHABLE"
        }
    except Exception:
        return {
            "ip": host_ip,
            "alive": False,
            "latency_ms": None,
            "status": "TIMEOUT"
        }
