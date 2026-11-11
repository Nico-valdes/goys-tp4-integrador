import re
from core import telemetry, firewall, ai_engine

def process_command(message: str) -> dict:
    """
    Interpreta comandos directos de ChatOps o deriva a inferencia semántica con IA (Ollama).
    Retorna un diccionario estructurado: { 'reply': str, 'action': str, 'data': dict, 'suggested_action': dict }
    """
    text = message.strip()
    
    # 1. Comando: /help o /ayuda
    if text in ["/ayuda", "/help", "/h"]:
        reply = (
            "**Comandos disponibles en la consola de ChatOps:**\n\n"
            "- `/status`: Diagnóstico de salud del clúster, latencia y telemetría de red.\n"
            "- `/analizar`: Ejecuta un análisis semántico del tráfico con el modelo local de IA.\n"
            "- `/reset` o `/limpiar`: Vacía los logs de Nginx y limpia el firewall para reiniciar pruebas.\n"
            "- `/bloquear <IP>`: Aplica una regla DROP en el firewall de kernel (DOCKER-USER).\n"
            "- `/desbloquear <IP>`: Remueve la regla de firewall y restablece el tráfico.\n"
            "- `/reglas`: Lista las IPs actualmente bloqueadas y motivos de mitigación.\n"
            "- `/logs`: Muestra las últimas peticiones registradas en el servidor web.\n"
            "- *Consultas libres:* Preguntas sobre protocolos, redes, Linux o estado del sistema."
        )
        return {"reply": reply, "action": "help", "data": None, "suggested_action": None}

    # 2. Comando: /reset o /limpiar
    if text in ["/reset", "/limpiar"]:
        telemetry.clear_logs()
        for ip in list(firewall.BLOCKED_IPS.keys()):
            firewall.unblock_ip(ip)
        reply = "Laboratorio reiniciado. Registros de Nginx vaciados (Total en 0) y reglas de firewall restablecidas."
        return {"reply": reply, "action": "reset", "data": None, "suggested_action": None}

    # 3. Comando: /status
    if text in ["/status", "/estado"]:
        ping_nginx = telemetry.ping_host("172.20.0.10")
        ping_attacker = telemetry.ping_host("172.20.0.99")
        metrics = telemetry.get_traffic_metrics(50000)
        ai_state = ai_engine.check_ai_status()
        
        reply = (
            "**Estado de la Infraestructura en Tiempo Real:**\n\n"
            f"● **Servidor Nginx (172.20.0.10):** `{ping_nginx['status']}` ({ping_nginx['latency_ms'] or 0} ms)\n"
            f"● **Nodo Atacante (172.20.0.99):** `{ping_attacker['status']}` ({ping_attacker['latency_ms'] or 0} ms)\n"
            f"● **Velocidad de Tráfico:** `{metrics.get('rps', 0)} req/s`\n"
            f"● **Motor LLM (Ollama):** `{ai_state['provider']}` (Modelo: `{ai_state['model']}`)\n\n"
            f"**Telemetría de Tráfico Acumulada:**\n"
            f"- Total de peticiones: **{metrics['total_requests']}**\n"
            f"- 200 OK: **{metrics['status_distribution']['200_ok']}** | 401/403: **{metrics['status_distribution']['401_unauthorized'] + metrics['status_distribution']['403_forbidden']}** | 404: **{metrics['status_distribution']['404_not_found']}**\n"
        )
        if metrics["suspect_ips"]:
            reply += f"\n**IPs con volumen sospechoso:** {', '.join(metrics['suspect_ips'])}"
        
        return {"reply": reply, "action": "status", "data": metrics, "suggested_action": None}

    # 4. Comando: /bloquear <ip>
    block_match = re.match(r"^/(bloquear|block)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", text)
    if block_match:
        target_ip = block_match.group("ip")
        res = firewall.block_ip(target_ip, reason="Mitigación manual vía ChatOps")
        reply = f"**Acción de Mitigación:** {res['message']}"
        return {"reply": reply, "action": "block", "data": res, "suggested_action": None}

    # 5. Comando: /desbloquear <ip>
    unblock_match = re.match(r"^/(desbloquear|unblock)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", text)
    if unblock_match:
        target_ip = unblock_match.group("ip")
        res = firewall.unblock_ip(target_ip)
        reply = f"**Acción de Firewall:** {res['message']}"
        return {"reply": reply, "action": "unblock", "data": res, "suggested_action": None}

    # 6. Comando: /reglas o /rules
    if text in ["/reglas", "/rules"]:
        rules = firewall.list_rules()
        if not rules:
            return {"reply": "**Firewall limpio:** No hay direcciones IP bloqueadas actualmente.", "action": "rules", "data": [], "suggested_action": None}
        
        reply = "**Políticas de Filtrado Activas en Firewall (DROP):**\n\n"
        for r in rules:
            reply += f"● **IP:** `{r['ip']}` | Motivo: *{r['reason']}* | Registrado: `{r['timestamp']}`\n"
        return {"reply": reply, "action": "rules", "data": rules, "suggested_action": None}

    # 7. Comando: /logs
    if text in ["/logs"]:
        recent_logs = telemetry.parse_logs(10)
        if not recent_logs:
            return {"reply": "No se registran eventos recientes en `access.log`.", "action": "logs", "data": [], "suggested_action": None}
        
        reply = "**Últimos registros de acceso procesados:**\n\n"
        for l in recent_logs[-8:]:
            reply += f"`{l['ip']}` → `{l['request']}` [{l['status']}] ({l['user_agent']})\n"
        return {"reply": reply, "action": "logs", "data": recent_logs, "suggested_action": None}

    # 8. Decisión de Inferencia: Análisis de Seguridad AIOps vs Consulta Conversacional
    analysis_keywords = ["/analizar", "analizar", "analiza", "ataque", "amenaza", "incidente", "forense", "tráfico", "trafico", "seguridad", "reporte"]
    is_analysis_request = any(k in text.lower() for k in analysis_keywords)

    if is_analysis_request:
        ai_result = ai_engine.analyze_traffic_with_ollama(prompt_custom=text)
        return {
            "reply": ai_result["reply"],
            "action": "ai_analysis",
            "data": {"model": ai_result.get("model")},
            "suggested_action": ai_result.get("suggested_action")
        }
    else:
        # Consulta conversacional técnica general
        chat_res = ai_engine.chat_with_assistant(text)
        return {
            "reply": chat_res["reply"],
            "action": "chat",
            "data": None,
            "suggested_action": None
        }
