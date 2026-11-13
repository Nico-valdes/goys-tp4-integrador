import re
from collections import Counter
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
            "**Consola de Operaciones ChatOps — Comandos Disponibles:**\n\n"
            "● **Monitoreo & Diagnóstico:**\n"
            "- `/status`: Estado de salud de la red, latencia ICMP y telemetría de tráfico.\n"
            "- `/top`: Lista las 5 direcciones IP con mayor volumen y porcentaje de tráfico.\n"
            "- `/inspeccionar <IP>`: Muestra el perfil forense y rutas visitadas por una IP específica.\n"
            "- `/logs`: Muestra las últimas peticiones registradas en el servidor Nginx.\n\n"
            "● **Mitigación & Firewall de Kernel:**\n"
            "- `/reglas`: Lista las políticas de filtrado activas en la cadena `DOCKER-USER`.\n"
            "- `/bloquear <IP>`: Aplica una regla DROP perimetral para aislar una IP.\n"
            "- `/desbloquear <IP>`: Remueve la regla de firewall y restablece la comunicación.\n\n"
            "● **Control de Laboratorio & AIOps:**\n"
            "- `/analizar`: Inferencia semántica con el LLM local para clasificar incidentes.\n"
            "- `/reset`: Vacía los logs de Nginx y limpia el firewall para reiniciar ensayos.\n\n"
            "● **Consultas Conversacionales:**\n"
            "Podés preguntar libremente sobre redes o el sistema (ej. *'¿Hay algún ataque activo?'*, *'¿Cómo funciona iptables en Docker?'*, *'¿Por qué 172.20.0.50 no fue bloqueada?'*)."
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
        ping_gateway = telemetry.ping_host("172.20.0.1")
        metrics = telemetry.get_traffic_metrics(50000)
        ai_state = ai_engine.check_ai_status()
        
        reply = (
            "**Estado de la Infraestructura en Tiempo Real:**\n\n"
            f"● **Servidor Nginx (172.20.0.10):** `{ping_nginx['status']}` ({ping_nginx['latency_ms'] or 0} ms)\n"
            f"● **Gateway de Red (172.20.0.1):** `{ping_gateway['status']}` ({ping_gateway['latency_ms'] or 0} ms)\n"
            f"● **Velocidad de Tráfico:** `{metrics.get('rps', 0)} req/s`\n"
            f"● **Motor LLM (Ollama):** `{ai_state['provider']}` (Modelo: `{ai_state['model']}`)\n\n"
            f"**Telemetría Acumulada:** Total peticiones: **{metrics['total_requests']}** (200 OK: {metrics['status_distribution']['200_ok']}, Errores 401/403/404: {metrics['status_distribution']['401_unauthorized'] + metrics['status_distribution']['403_forbidden'] + metrics['status_distribution']['404_not_found']})"
        )
        if metrics["top_ips"]:
            ip_summary = ", ".join([f"{item['ip']} ({item['count']} reqs)" for item in metrics["top_ips"][:3]])
            reply += f"\n● **Orígenes activos:** {ip_summary}"
        
        return {"reply": reply, "action": "status", "data": metrics, "suggested_action": None}

    # 4. Comando: /top
    if text in ["/top", "/ips"]:
        metrics = telemetry.get_traffic_metrics(50000)
        top_ips = metrics.get("top_ips", [])
        total = metrics.get("total_requests", 0)
        if not top_ips or total == 0:
            return {"reply": "No hay actividad de tráfico registrada en el buffer de red.", "action": "top", "data": [], "suggested_action": None}

        reply = f"**Top Orígenes de Tráfico en Red (Total: {total} peticiones):**\n\n"
        for idx, item in enumerate(top_ips, 1):
            ip = item["ip"]
            cnt = item["count"]
            pct = round((cnt / total) * 100, 1)
            is_blocked = firewall.is_blocked(ip)
            status_tag = "`BLOQUEADO (DROP)`" if is_blocked else "`PERMITIDO`"
            reply += f"{idx}. **{ip}** — {cnt} reqs ({pct}%) | Estado: {status_tag}\n"

        return {"reply": reply, "action": "top", "data": top_ips, "suggested_action": None}

    # 5. Comando: /inspeccionar <ip> o /origen <ip>
    inspect_match = re.match(r"^/(inspeccionar|origen|inspect)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", text)
    if inspect_match:
        target_ip = inspect_match.group("ip")
        logs = telemetry.parse_logs(10000)
        ip_logs = [l for l in logs if l.get("ip") == target_ip]
        if not ip_logs:
            return {"reply": f"No se registran eventos para la IP `{target_ip}` en los logs de acceso.", "action": "inspect", "data": None, "suggested_action": None}

        cnt = len(ip_logs)
        status_c = Counter([l["status"] for l in ip_logs])
        ua_c = Counter([l["user_agent"] for l in ip_logs])
        paths_c = Counter([l["request"] for l in ip_logs])
        is_blocked = firewall.is_blocked(target_ip)

        reply = (
            f"**Perfil Forense del Origen: `{target_ip}`**\n\n"
            f"● **Total Solicitudes:** {cnt}\n"
            f"● **Estado en Firewall:** `{'BLOQUEADO (DROP)' if is_blocked else 'PERMITIDO'}`\n"
            f"● **Códigos HTTP:** 200={status_c.get(200, 0)}, 401={status_c.get(401, 0)}, 403={status_c.get(403, 0)}, 404={status_c.get(404, 0)}\n"
            f"● **Rutas más solicitadas:** {', '.join([p for p, _ in paths_c.most_common(4)])}\n"
            f"● **User-Agent:** `{ua_c.most_common(1)[0][0] if ua_c else 'N/A'}`\n"
        )
        return {"reply": reply, "action": "inspect", "data": {"ip": target_ip, "count": cnt}, "suggested_action": None}

    # 6. Comando: /bloquear <ip>
    block_match = re.match(r"^/(bloquear|block|mitigar)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", text)
    if block_match:
        target_ip = block_match.group("ip")
        if target_ip in ["127.0.0.1", "172.20.0.10", "172.20.0.1"]:
            return {"reply": f"Operación denegada: `{target_ip}` es una dirección de infraestructura protegida (Lista Blanca).", "action": "block_rejected", "data": None, "suggested_action": None}
        res = firewall.block_ip(target_ip, reason="Mitigación manual vía ChatOps")
        reply = f"**Acción de Mitigación:** {res['message']}"
        return {"reply": reply, "action": "block", "data": res, "suggested_action": None}

    # 7. Comando: /desbloquear <ip>
    unblock_match = re.match(r"^/(desbloquear|unblock)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", text)
    if unblock_match:
        target_ip = unblock_match.group("ip")
        res = firewall.unblock_ip(target_ip)
        reply = f"**Acción de Firewall:** {res['message']}"
        return {"reply": reply, "action": "unblock", "data": res, "suggested_action": None}

    # 8. Comando: /reglas o /rules
    if text in ["/reglas", "/rules"]:
        rules = firewall.list_rules()
        if not rules:
            return {"reply": "**Firewall limpio:** No hay direcciones IP bloqueadas actualmente.", "action": "rules", "data": [], "suggested_action": None}
        
        reply = "**Políticas de Filtrado Activas en Firewall (DROP):**\n\n"
        for r in rules:
            reply += f"● **IP:** `{r['ip']}` | Motivo: *{r['reason']}* | Registrado: `{r['timestamp']}`\n"
        return {"reply": reply, "action": "rules", "data": rules, "suggested_action": None}

    # 9. Comando: /logs
    if text in ["/logs"]:
        recent_logs = telemetry.parse_logs(10)
        if not recent_logs:
            return {"reply": "No se registran eventos recientes en `access.log`.", "action": "logs", "data": [], "suggested_action": None}
        
        reply = "**Últimos registros de acceso procesados:**\n\n"
        for l in recent_logs[-8:]:
            reply += f"`{l['ip']}` → `{l['request']}` [{l['status']}] ({l['user_agent']})\n"
        return {"reply": reply, "action": "logs", "data": recent_logs, "suggested_action": None}

    # 10. Decisión de Inferencia: Análisis de Seguridad AIOps vs Consulta Conversacional
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
        # Contexto en vivo para enriquecer la respuesta del asistente
        rules = firewall.list_rules()
        blocked_ips = [r["ip"] for r in rules]
        metrics = telemetry.get_traffic_metrics(1000)
        context_str = f"- Total requests en buffer: {metrics['total_requests']}\n- IPs bloqueadas actualmente en firewall: {', '.join(blocked_ips) or 'Ninguna'}\n- Top IPs activas: {', '.join([item['ip'] for item in metrics['top_ips'][:3]]) or 'Sin tráfico'}"
        
        chat_res = ai_engine.chat_with_assistant(text, context=context_str)
        return {
            "reply": chat_res["reply"],
            "action": "chat",
            "data": None,
            "suggested_action": None
        }
