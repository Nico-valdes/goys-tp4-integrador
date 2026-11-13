import os
import subprocess
from datetime import datetime
from typing import List, Dict

# Almacén en memoria de reglas y bloqueos activos
BLOCKED_IPS: Dict[str, dict] = {}

def execute_iptables_command(args: List[str]) -> bool:
    """Intenta ejecutar un comando de iptables en el kernel de Linux."""
    for binary in ["iptables", "iptables-legacy"]:
        try:
            cmd = [binary] + args
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
    return False

def block_ip(ip: str, reason: str = "Mitigación manual / ChatOps") -> dict:
    """
    Aplica una regla de bloqueo DROP para una dirección IP específica.
    Inserta la regla en la cadena INPUT (o DOCKER-USER) para filtrar a nivel de kernel Netfilter.
    """
    clean_ip = ip.strip()
    if not clean_ip:
        return {"success": False, "message": "Dirección IP inválida."}
    
    # 1. Regla en kernel: iptables -I INPUT -s <IP> -j DROP
    applied_kernel = execute_iptables_command(["-I", "INPUT", "-s", clean_ip, "-j", "DROP"])
    if not applied_kernel:
        applied_kernel = execute_iptables_command(["-I", "DOCKER-USER", "-s", clean_ip, "-j", "DROP"])

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

    status_str = "en kernel con éxito" if applied_kernel else "en registro (simulación)"
    return {
        "success": True,
        "message": f"IP {clean_ip} bloqueada {status_str} (Acción: DROP).",
        "data": record
    }

def unblock_ip(ip: str) -> dict:
    """Remueve la regla de bloqueo para una dirección IP."""
    clean_ip = ip.strip()
    if clean_ip not in BLOCKED_IPS:
        return {"success": False, "message": f"La IP {clean_ip} no se encuentra en la lista de bloqueos."}

    # Intentamos remover la regla del kernel (tanto en INPUT como en DOCKER-USER)
    execute_iptables_command(["-D", "INPUT", "-s", clean_ip, "-j", "DROP"])
    execute_iptables_command(["-D", "DOCKER-USER", "-s", clean_ip, "-j", "DROP"])

    deleted = BLOCKED_IPS.pop(clean_ip, None)
    return {
        "success": True,
        "message": f"IP {clean_ip} desbloqueada y tráfico restablecido.",
        "data": deleted
    }

def flush_all_rules() -> bool:
    """Elimina todas las reglas inyectadas en INPUT para restablecer el laboratorio."""
    BLOCKED_IPS.clear()
    return execute_iptables_command(["-F", "INPUT"])

def list_rules() -> List[dict]:
    """Retorna todas las reglas y direcciones IP bloqueadas actualmente."""
    return list(BLOCKED_IPS.values())

def is_blocked(ip: str) -> bool:
    """Verifica si una IP está marcada como bloqueada."""
    return ip.strip() in BLOCKED_IPS

