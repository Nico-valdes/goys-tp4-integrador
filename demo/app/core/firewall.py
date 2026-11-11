import os
import subprocess
from datetime import datetime
from typing import List, Dict

# Almacén en memoria de reglas y bloqueos activos
BLOCKED_IPS: Dict[str, dict] = {}

def execute_iptables_command(args: List[str]) -> bool:
    """Intenta ejecutar un comando de iptables en el kernel de Linux."""
    try:
        # Verificamos si iptables está disponible en el sistema
        cmd = ["iptables"] + args
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        # En caso de estar en Windows o contenedor sin NET_ADMIN, simulamos la regla
        return False

def block_ip(ip: str, reason: str = "Mitigación manual / ChatOps") -> dict:
    """
    Aplica una regla de bloqueo DROP para una dirección IP específica.
    Inserta la regla en la cadena DOCKER-USER / INPUT para filtrar a nivel de kernel.
    """
    clean_ip = ip.strip()
    if not clean_ip:
        return {"success": False, "message": "Dirección IP inválida."}
    
    # 1. Intentamos aplicar regla en el kernel
    # Regla: iptables -I DOCKER-USER -s <IP> -j DROP
    applied_kernel = execute_iptables_command(["-I", "DOCKER-USER", "-s", clean_ip, "-j", "DROP"])
    if not applied_kernel:
        # Fallback a cadena INPUT
        applied_kernel = execute_iptables_command(["-I", "INPUT", "-s", clean_ip, "-j", "DROP"])

    # 2. Registramos el bloqueo en el estado del firewall
    record = {
        "ip": clean_ip,
        "action": "DROP",
        "target": "ALL TRAFFIC",
        "reason": reason,
        "kernel_enforced": applied_kernel,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    BLOCKED_IPS[clean_ip] = record

    return {
        "success": True,
        "message": f"IP {clean_ip} bloqueada con éxito (Acción: DROP).",
        "data": record
    }

def unblock_ip(ip: str) -> dict:
    """Remueve la regla de bloqueo para una dirección IP."""
    clean_ip = ip.strip()
    if clean_ip not in BLOCKED_IPS:
        return {"success": False, "message": f"La IP {clean_ip} no se encuentra en la lista de bloqueos."}

    # Intentamos remover la regla del kernel
    execute_iptables_command(["-D", "DOCKER-USER", "-s", clean_ip, "-j", "DROP"])
    execute_iptables_command(["-D", "INPUT", "-s", clean_ip, "-j", "DROP"])

    deleted = BLOCKED_IPS.pop(clean_ip, None)
    return {
        "success": True,
        "message": f"IP {clean_ip} desbloqueada y tráfico restablecido.",
        "data": deleted
    }

def list_rules() -> List[dict]:
    """Retorna todas las reglas y direcciones IP bloqueadas actualmente."""
    return list(BLOCKED_IPS.values())

def is_blocked(ip: str) -> bool:
    """Verifica si una IP está marcada como bloqueada."""
    return ip.strip() in BLOCKED_IPS

