import os
import time
import json
import re
import requests
from typing import List, Dict, Optional
from core import telemetry

OLLAMA_ENDPOINTS = [
    "http://host.docker.internal:11434",
    "http://172.17.0.1:11434",
    "http://localhost:11434",
    "http://127.0.0.1:11434"
]

PREFERRED_MODELS = ["llama3.2:3b", "qwen2.5:3b", "qwen2.5:1.5b", "llama3.2:1b"]

# Regex estricto de IPv4 para validación dinámica
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

SYSTEM_PROMPT = """Eres el analista de seguridad y AIOps del centro de operaciones (SOC) para servidores web.
Tu función es interpretar la telemetría en vivo de Nginx, traducir de forma clara qué está ocurriendo a nivel de red y dar tu opinión y veredicto técnico.

TAXONOMÍA DE SEVERIDAD:
- CRÍTICA: DoS Volumétrico o denegación de servicio activa (inundación de peticiones HTTP, ráfagas masivas con bots como AttackBot, saturación de peticiones incluso con código 200 OK). Requiere BLOQUEO INMEDIATO.
- ALTA: Escaneo de directorios administrativos (/admin, /.env, /backup.sql) y fuerza bruta activa (DirBuster, 401/404 reiterados). Requiere BLOQUEO INMEDIATO.
- MEDIA: Múltiples errores 404 aislados de usuarios sin herramientas automatizadas evidentes. Monitoreo pasivo.
- BAJA / INFORMATIVA: Tráfico regular de usuarios reales (navegadores Chrome, Firefox, bajo volumen < 30 peticiones, 0 errores de autenticación). MONITOREO PASIVO. NO BLOQUEAR.

REGLAS DE FORMATO (Obligatorio respetar estos 6 encabezados en negrita):
**Incidente:** [Vector identificado o Tráfico Nominal de Usuarios]

**Severidad:** [CRÍTICA | ALTA | MEDIA | BAJA]

**Origen y Patrón:** [IP analizada, porcentaje de concentración y User-Agent]

**Impacto en Infraestructura:** [Métricas reales: peticiones, bytes transferidos, diversidad de rutas y latencia del servidor]

**Muestra Forense:** [Líneas reales de petición extraídas del log]

**Evaluación de la IA:** [Tu opinión y dictamen técnico en 2 o 3 oraciones: explica qué busca este tráfico, si pone en riesgo la infraestructura y la justificación de tu decisión]

**Acción Recomendada:** [BLOQUEO INMEDIATO (DROP) | MONITOREO PASIVO] [ACCION:BLOQUEAR:<IP>]

Sé riguroso, técnico y directo. Usa exclusivamente los datos reales de la telemetría."""

def get_active_ollama_url() -> Optional[str]:
    for url in OLLAMA_ENDPOINTS:
        try:
            res = requests.get(f"{url}/api/tags", timeout=1.0)
            if res.status_code == 200:
                return url
        except requests.exceptions.RequestException:
            continue
    return None

def check_ai_status() -> dict:
    active_url = get_active_ollama_url()
    if active_url:
        try:
            res = requests.get(f"{active_url}/api/tags", timeout=1.5)
            installed_models = [m.get("name") for m in res.json().get("models", [])]
            
            chosen_model = "llama3.2:3b"
            for pref in PREFERRED_MODELS:
                match = next((m for m in installed_models if pref in m), None)
                if match:
                    chosen_model = match
                    break
            if not installed_models:
                chosen_model = "Ninguno instalado"

            return {
                "online": True,
                "provider": "Ollama Local (On-Premise)",
                "endpoint": active_url,
                "model": chosen_model,
                "available_models": installed_models
            }
        except Exception:
            pass
    
    return {
        "online": False,
        "provider": "Ollama Desconectado",
        "endpoint": "localhost:11434 (Inactivo)",
        "model": "Ninguno",
        "available_models": []
    }

def extract_dynamic_target_ip(ai_text: str, digest: dict) -> Optional[str]:
    """
    Extrae la IP atacante de forma 100% dinámica a partir de la inferencia del modelo
    o la telemetría, sin valores fijos ni IPs predeterminadas.
    """
    # 1. Buscar token explícito [ACCION:BLOQUEAR:<IP>]
    action_match = re.search(r"\[ACCION:BLOQUEAR:(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", ai_text)
    if action_match:
        ip = action_match.group("ip")
        if ip not in ["127.0.0.1", "172.20.0.10"]:  # No bloquear localhost ni el propio servidor
            return ip

    # 2. Buscar IP mencionada en la línea de 'Origen:' de la IA
    for line in ai_text.split("\n"):
        if "origen" in line.lower():
            found_ips = IPV4_REGEX.findall(line)
            for ip in found_ips:
                if ip not in ["127.0.0.1", "172.20.0.10", "172.20.0.1"]:
                    return ip

    # 3. Fallback dinámico a la IP de mayor concentración estadística de la telemetría
    top_ip = digest.get("top_ip")
    if top_ip and top_ip not in ["127.0.0.1", "172.20.0.10", "172.20.0.1"]:
        return top_ip

    return None

def analyze_traffic_with_ollama(logs: Optional[List[Dict]] = None, prompt_custom: Optional[str] = None, target_ip: Optional[str] = None) -> dict:
    ai_state = check_ai_status()
    
    if not ai_state["online"]:
        return {
            "success": False,
            "ollama_online": False,
            "model": "N/A",
            "inference_time_ms": 0,
            "reply": "Inferencia no disponible: No se detecta instancia de Ollama activa en localhost:11434.",
            "suggested_action": None
        }

    active_url = ai_state["endpoint"]
    model_name = ai_state["model"]

    digest = telemetry.generate_telemetry_digest(2000, target_ip=target_ip)
    
    if digest.get("total_requests", 0) == 0:
        return {
            "success": True,
            "ollama_online": True,
            "model": model_name,
            "inference_time_ms": 0,
            "reply": "**Reporte de Tráfico AIOps**\n\n**Incidente:** Tráfico Nominal\n\n**Severidad:** BAJA / INFORMATIVA\n\nNo se observan anomalías en el buffer de red.",
            "suggested_action": None
        }

    top_ip = digest.get("top_ip", "127.0.0.1")
    top_ip_count = digest.get("top_ip_count", 0)
    concentration = digest.get("concentration_pct", 0.0)
    auth_errors = digest["status_distribution"].get("auth_errors_401_403", 0)
    not_found = digest["status_distribution"].get("not_found_404", 0)
    ok_200 = digest["status_distribution"].get("200_ok", 0)
    uas_str = " ".join(digest.get("top_user_agents", [])).lower()
    has_bot_ua = any(b in uas_str for b in ["attackbot", "bot", "python", "curl", "dirbuster", "nikto", "sqlmap"])
    has_sensitive_paths = len(digest.get("sensitive_paths_targeted", [])) > 0

    # Clasificación determinista Capa 1 (Sensor SOC en Red):
    if (auth_errors >= 3 or (not_found >= 5 and has_sensitive_paths) or has_sensitive_paths):
        c1_diagnosis = f"ALERTA SOC: Escaneo activo de directorios y fuerza bruta L7 desde IP {top_ip} ({auth_errors} errores de autenticación/rutas críticas)."
        c1_guidance = f"Clasificar como Severidad ALTA. Acción recomendada: BLOQUEO INMEDIATO (DROP) [ACCION:BLOQUEAR:{top_ip}]."
    elif (has_bot_ua and top_ip_count >= 20) or (top_ip_count >= 40 and concentration >= 45.0):
        c1_diagnosis = f"ALERTA SOC: Ataque DoS Volumétrico (HTTP Flood) desde IP {top_ip} ({top_ip_count} peticiones masivas, {concentration}% del tráfico activo)."
        c1_guidance = f"Clasificar como Severidad CRÍTICA. Acción recomendada: BLOQUEO INMEDIATO (DROP) [ACCION:BLOQUEAR:{top_ip}]."
    elif auth_errors == 0 and not has_sensitive_paths and not has_bot_ua and concentration < 45.0:
        c1_diagnosis = f"TELEMETRÍA NOMINAL: Navegación estándar de usuario legítimo desde IP {top_ip} (navegadores comerciales, bajo impacto en red, sin patrones hostiles)."
        c1_guidance = "Clasificar como Severidad BAJA. Incidente: Tráfico Nominal de Usuarios. Acción recomendada: MONITOREO PASIVO. NO BLOQUEAR."
    else:
        c1_diagnosis = f"EVALUACIÓN HEURÍSTICA: Tráfico registrado desde {top_ip} con volumen moderado ({top_ip_count} reqs)."
        c1_guidance = "Analizar según taxonomía y determinar si amerita mitigación."

    ping_res = telemetry.ping_host("172.20.0.10")
    latency_ms = ping_res.get("latency_ms", 1.5)
    samples_formatted = "\n".join([f"  ● {s}" for s in digest.get("samples", [])]) or "  ● Ninguna registrada"

    telemetry_summary = f"""Telemetría del servidor web Nginx (Ráfaga Activa de {top_ip_count} peticiones del origen {top_ip} | Histórico acumulado: {digest['total_requests']}):
- Origen evaluado: {top_ip} ({digest['concentration_pct']}% del tráfico activo con {top_ip_count} peticiones registradas)
- Distribución de estados HTTP: 200 OK={digest['status_distribution']['200_ok']}, 401/403={digest['status_distribution']['auth_errors_401_403']}, 404={digest['status_distribution']['not_found_404']}, 5xx={digest['status_distribution'].get('server_errors_5xx', 0)}
- Diversidad de rutas: {digest.get('unique_paths_count', 1)} ruta(s) distinta(s). Rutas sensibles: {', '.join(digest['sensitive_paths_targeted']) or 'Ninguna'}
- Carga de datos: {round(digest.get('total_bytes', 0) / 1024, 1)} KB transferidos | Tiempo medio de respuesta Nginx: {digest.get('avg_response_time_ms', 0.0)} ms
- Latencia actual del servidor Nginx: {latency_ms} ms (Estado: {ping_res.get('status', 'ONLINE')})
- User-Agents en ráfaga: {', '.join(digest['top_user_agents'])}

Muestra de peticiones reales en log:
{samples_formatted}

[Diagnóstico Perimétrico Capa 1 - Heurística]:
{c1_diagnosis}
Guía de clasificación: {c1_guidance}
"""

    user_query = prompt_custom or "Analizar la telemetría, clasificar la severidad del tráfico y determinar la acción requerida."

    full_prompt = f"""{telemetry_summary}

Instrucción del operador: {user_query}
"""

    payload = {
        "model": model_name,
        "system": SYSTEM_PROMPT,
        "prompt": full_prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 550
        }
    }

    start_time = time.time()
    try:
        response = requests.post(f"{active_url}/api/generate", json=payload, timeout=60)
        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        if response.status_code == 200:
            ai_text = response.json().get("response", "").strip()
            
            # Normalizar encabezados en negrita
            for header in ["Incidente:", "Severidad:", "Origen y Patrón:", "Origen:", "Impacto en Infraestructura:", "Muestra Forense:", "Evaluación de la IA:", "Acción Recomendada:", "Mitigación:"]:
                if header in ai_text and f"**{header}**" not in ai_text:
                    ai_text = ai_text.replace(header, f"**{header}**")

            # Extracción 100% DINÁMICA de la IP objetivo
            target_ip = extract_dynamic_target_ip(ai_text, digest)
            if not target_ip:
                target_ip = digest.get("top_ip")
            
            # Evaluar si requiere acción de bloqueo según la respuesta del LLM
            text_upper = ai_text.upper()
            text_lower = ai_text.lower()
            
            is_explicit_low = any(k in text_upper for k in ["SEVERIDAD: BAJA", "SEVERIDAD:** BAJA", "MONITOREO PASIVO", "TRÁFICO NOMINAL", "TRAFICO NOMINAL", "NO BLOQUEAR"])
            is_critical_or_high = not is_explicit_low and (
                any(k in text_upper for k in ["CRÍTICA", "CRITICA", "ALTA", "BLOQUEO INMEDIATO", "DROP", "ACCION:BLOQUEAR"]) or
                any(k in text_lower for k in ["bloqueo inmediato", "aplicar drop", "ataque dos", "flood", "fuerza bruta"])
            )

            # Limpiar token crudo del texto final
            ai_text = re.sub(r"\[ACCION:BLOQUEAR:[^\]]+\]", "", ai_text).strip()

            suggested_action = None
            if is_critical_or_high and target_ip and target_ip not in ["127.0.0.1", "172.20.0.10", "172.20.0.1"]:
                suggested_action = {
                    "type": "block",
                    "ip": target_ip,
                    "label": f"Aplicar política DROP para {target_ip}"
                }

            return {
                "success": True,
                "ollama_online": True,
                "model": model_name,
                "inference_time_ms": elapsed_ms,
                "reply": f"**Reporte de Seguridad AIOps**\n*{model_name} · Inferencia en {elapsed_ms} ms*\n\n{ai_text}",
                "suggested_action": suggested_action
            }
    except Exception as e:
        return {
            "success": False,
            "ollama_online": True,
            "model": model_name,
            "inference_time_ms": 0,
            "reply": f"Error durante la inferencia con el modelo local: {str(e)}",
            "suggested_action": None
        }

    return {
        "success": False,
        "ollama_online": False,
        "model": "N/A",
        "inference_time_ms": 0,
        "reply": "Respuesta no obtenida del servicio local.",
        "suggested_action": None
    }

def chat_with_assistant(message: str, context: Optional[str] = None) -> dict:
    """
    Modo conversacional general para ChatOps. Responde dudas técnicas del operador
    sobre la infraestructura, iptables, Docker o redes sin imponer la plantilla de incidente.
    """
    ai_state = check_ai_status()
    if not ai_state["online"]:
        return {
            "success": False,
            "reply": "Servicio de asistencia local no disponible: Ollama inactivo.",
            "suggested_action": None
        }

    active_url = ai_state["endpoint"]
    model_name = ai_state["model"]

    chat_system = (
        "Eres el Asistente Operativo ChatOps de la plataforma GOYS (UTN FR La Plata).\n"
        "Asistes al operador de red respondiendo consultas técnicas sobre la topología de red virtual (172.20.0.0/24),\n"
        "servidor Nginx (172.20.0.10), firewall iptables (cadena DOCKER-USER en Netfilter), Docker y protocolos L2/L3/L7.\n"
        "Responde de forma concisa, técnica y directa, sin emojis ni formalismos innecesarios.\n"
        "Si te saludan o te hacen una pregunta general o técnica, responde naturalmente sin generar plantillas de incidentes."
    )

    full_prompt = message
    if context:
        full_prompt = f"Contexto operativo en vivo de la red:\n{context}\n\nConsulta del operador:\n{message}"

    payload = {
        "model": model_name,
        "system": chat_system,
        "prompt": full_prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 250
        }
    }

    try:
        response = requests.post(f"{active_url}/api/generate", json=payload, timeout=60)
        if response.status_code == 200:
            text = response.json().get("response", "").strip()
            return {
                "success": True,
                "reply": text,
                "suggested_action": None
            }
    except Exception as e:
        return {
            "success": False,
            "reply": f"Error al procesar la consulta con el modelo local: {str(e)}",
            "suggested_action": None
        }

    return {
        "success": False,
        "reply": "No se obtuvo respuesta del modelo local.",
        "suggested_action": None
    }
