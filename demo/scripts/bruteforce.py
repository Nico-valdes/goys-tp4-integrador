#!/usr/bin/env python3
"""
Simulador de Escaneo y Fuerza Bruta HTTP
Envía peticiones continuas hacia endpoints protegidos o sensibles (/admin, /.env, /backup.sql)
Permite especificar la IP de origen mediante --ip para simular orígenes desconocidos.
"""

import time
import argparse
import subprocess
import requests
from requests.adapters import HTTPAdapter

TARGET_BASE = "http://172.20.0.10"
ENDPOINTS = [
    "/admin",
    "/admin/login",
    "/admin/config.php",
    "/api/secret",
    "/wp-login.php",
    "/backup.sql",
    "/.env",
    "/server-status"
]

class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_ip, **kwargs):
        self.source_ip = source_ip
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['source_address'] = (self.source_ip, 0)
        return super().init_poolmanager(*args, **kwargs)

def ensure_ip_alias(ip):
    try:
        subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", "eth0"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Simulador de Fuerza Bruta y Escaneo L7")
    parser.add_argument("--ip", default="172.20.0.120", help="Dirección IP de origen del atacante (default: 172.20.0.120)")
    parser.add_argument("--attempts", type=int, default=24, help="Cantidad de intentos (default: 24)")
    args = parser.parse_args()

    source_ip = args.ip
    if source_ip in ["172.20.0.10", "172.20.0.1"]:
        print(f"[!] Error: {source_ip} es la IP del servidor víctima o gateway.")
        print("    No se puede usar como IP de origen del atacante. Use una IP de cliente (ej: 172.20.0.120, 172.20.0.88).")
        return

    ensure_ip_alias(source_ip)

    session = requests.Session()
    try:
        adapter = SourceAddressAdapter(source_ip)
        session.mount("http://", adapter)
    except Exception as e:
        print(f"[!] No se pudo enlazar a {source_ip}, usando socket por defecto: {e}")

    print("=" * 60)
    print(f"🕵️ INICIANDO ESCANEO DE RECONOCIMIENTO Y FUERZA BRUTA")
    print(f"🎯 Servidor objetivo: {TARGET_BASE} | IP Origen: {source_ip}")
    print("=" * 60)

    for i in range(1, args.attempts + 1):
        endpoint = ENDPOINTS[(i - 1) % len(ENDPOINTS)]
        url = f"{TARGET_BASE}{endpoint}"
        headers = {
            "User-Agent": f"DirBuster-Scanner/2.0-Attempt-{i}"
        }
        try:
            res = session.get(url, headers=headers, timeout=2.0)
            print(f"[{i:02d}/{args.attempts:02d}] {source_ip} -> GET {endpoint:<20} -> Código: {res.status_code}")
        except requests.exceptions.RequestException:
            print(f"[{i:02d}/{args.attempts:02d}] {source_ip} -> GET {endpoint:<20} -> [BLOQUEADO / TIMEOUT]")
        time.sleep(0.15)

    print("=" * 60)
    print(f"✅ Escaneo desde {source_ip} completado.")
    print("=" * 60)

if __name__ == "__main__":
    main()
