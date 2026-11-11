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

SYSTEM_PROMPT = """Eres un motor de ciberseguridad y análisis de tráfico (AIOps / SOC) para servidores web.
Tu función es clasificar la telemetría agregada de los registros de acceso y calificar el nivel de amenaza.

TAXONOMÍA DE SEVERIDAD:
- CRÍTICA: DoS Volumétrico o denegación de servicio activa que degrade recursos. Requiere BLOQUEO INMEDIATO.
- ALTA: Escaneo de directorios administrativos (/admin, /.env, /backup.sql) y fuerza bruta activa. Requiere BLOQUEO INMEDIATO.
- MEDIA: Múltiples errores 404 de rutas aisladas sin herramientas automatizadas evidentes.
- BAJA / INFORMATIVA: Tráfico regular de usuarios reales. Monitoreo pasivo.

REGLAS DE FORMATO (Obligatorio respetar estos 5 encabezados):
**Incidente:** [Vector identificado]

**Severidad:** [CRÍTICA | ALTA | MEDIA | BAJA]

**Origen:** [IP atacante y User-Agent identificado]

**Evidencia:** [Métricas, rutas sensibles atacadas y códigos HTTP observados]

**Acción Recomendada:** [BLOQUEO INMEDIATO (DROP) | MONITOREO PASIVO] [ACCION:BLOQUEAR:<IP>]

Sé riguroso y conciso. No repitas tablas numéricas extensas."""

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

def analyze_traffic_with_ollama(logs: Optional[List[Dict]] = None, prompt_custom: Optional[str] = None) -> dict:
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

    digest = telemetry.generate_telemetry_digest(150)
    
    if digest.get("total_requests", 0) == 0:
        return {
            "success": True,
            "ollama_online": True,
            "model": model_name,
            "inference_time_ms": 0,
            "reply": "**Reporte de Tráfico AIOps**\n\n**Incidente:** Tráfico Nominal\n\n**Severidad:** BAJA / INFORMATIVA\n\nNo se observan anomalías en el buffer de red.",
            "suggested_action": None
        }

    telemetry_summary = f"""Telemetría del servidor web (Ráfaga Activa de {digest.get('recent_window_requests', digest['total_requests'])} peticiones | Histórico acumulado: {digest['total_requests']}):
- IP dominante en ráfaga: {digest['top_ip']} ({digest['concentration_pct']}% con {digest['top_ip_count']} requests)
- Distribución de estados HTTP en ráfaga: 200 OK={digest['status_distribution']['200_ok']}, 401/403={digest['status_distribution']['auth_errors_401_403']}, 404={digest['status_distribution']['not_found_404']}
- User-Agents en ráfaga: {', '.join(digest['top_user_agents'])}
- Rutas sensibles bajo prueba en ráfaga: {', '.join(digest['sensitive_paths_targeted']) or 'Ninguna detectada'}
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
            "num_predict": 300
        }
    }

    start_time = time.time()
    try:
        response = requests.post(f"{active_url}/api/generate", json=payload, timeout=25)
        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        if response.status_code == 200:
            ai_text = response.json().get("response", "").strip()
            
            # Normalizar encabezados en negrita
            for header in ["Incidente:", "Severidad:", "Origen:", "Evidencia:", "Acción Recomendada:", "Mitigación:"]:
                if header in ai_text and f"**{header}**" not in ai_text:
                    ai_text = ai_text.replace(header, f"**{header}**")

            # Extracción 100% DINÁMICA de la IP objetivo
            target_ip = extract_dynamic_target_ip(ai_text, digest)
            
            # Evaluar si requiere acción de bloqueo según la respuesta del LLM
            is_critical = any(sev in ai_text.upper() for sev in ["CRÍTICA", "CRITICA", "ALTA"]) or \
                          any(w in ai_text.lower() for w in ["bloqueo inmediato", "drop", "dos", "escaneo", "fuerza bruta"])

            # Limpiar token crudo del texto final
            ai_text = re.sub(r"\[ACCION:BLOQUEAR:[^\]]+\]", "", ai_text).strip()

            suggested_action = None
            if is_critical and target_ip:
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

def chat_with_assistant(message: str) -> dict:
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
        "Asistes al operador de red respondiendo consultas técnicas sobre la topología (172.20.0.0/24),\n"
        "servidor Nginx (172.20.0.10), nodo atacante (172.20.0.99), firewall iptables (cadena DOCKER-USER) y protocolos L2/L3/L7.\n"
        "Responde de forma concisa, técnica y directa, sin emojis ni formalismos innecesarios.\n"
        "Si te saludan o te hacen una pregunta general, responde naturalmente como asistente técnico sin generar plantillas de incidentes."
    )

    payload = {
        "model": model_name,
        "system": chat_system,
        "prompt": message,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 250
        }
    }

    try:
        response = requests.post(f"{active_url}/api/generate", json=payload, timeout=20)
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
