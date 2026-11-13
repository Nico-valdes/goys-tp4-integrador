#!/usr/bin/env python3
"""
Simulador de Tráfico Legítimo de Usuario
Envía peticiones HTTP nominales hacia rutas válidas con User-Agents de navegadores comerciales,
demostrando que el sistema AIOps no bloquea tráfico válido (Cero Falsos Positivos).
"""

import sys
import time
import argparse
import subprocess
import requests
from requests.adapters import HTTPAdapter

TARGET_BASE = "http://172.20.0.10"
VALID_ENDPOINTS = [
    "/",
    "/index.html",
    "/",
    "/index.html"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
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
    parser = argparse.ArgumentParser(description="Simulador de Navegación Legítima")
    parser.add_argument("--ip", default="172.20.0.50", help="Dirección IP de origen para el cliente legítimo (default: 172.20.0.50)")
    parser.add_argument("--count", type=int, default=15, help="Cantidad de peticiones a enviar (default: 15)")
    parser.add_argument("--interval", type=float, default=0.4, help="Intervalo entre peticiones en segundos (default: 0.4)")
    args = parser.parse_args()

    source_ip = args.ip
    ensure_ip_alias(source_ip)

    session = requests.Session()
    try:
        adapter = SourceAddressAdapter(source_ip)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    except Exception as e:
        print(f"[!] No se pudo enlazar a {source_ip}, usando IP local por defecto: {e}")

    print("=" * 60)
    print(f"👤 INICIANDO NAVEGACIÓN DE CLIENTE LEGÍTIMO")
    print(f"🌐 IP de Origen: {source_ip} | Destino: {TARGET_BASE}")
    print(f"📦 Peticiones: {args.count} | Intervalo: {args.interval}s")
    print("=" * 60)

    success_count = 0
    blocked_count = 0

    for i in range(1, args.count + 1):
        endpoint = VALID_ENDPOINTS[(i - 1) % len(VALID_ENDPOINTS)]
        ua = USER_AGENTS[(i - 1) % len(USER_AGENTS)]
        headers = {"User-Agent": ua}
        url = f"{TARGET_BASE}{endpoint}"

        try:
            start = time.time()
            res = session.get(url, headers=headers, timeout=2.0)
            elapsed = round((time.time() - start) * 1000, 1)
            if res.status_code == 200:
                success_count += 1
                print(f"[{i:02d}/{args.count:02d}] {source_ip} -> GET {endpoint:<12} [{res.status_code} OK] ({elapsed}ms)")
            else:
                print(f"[{i:02d}/{args.count:02d}] {source_ip} -> GET {endpoint:<12} [HTTP {res.status_code}]")
        except requests.exceptions.RequestException:
            blocked_count += 1
            print(f"[{i:02d}/{args.count:02d}] {source_ip} -> GET {endpoint:<12} [BLOQUEADO / TIMEOUT]")

        time.sleep(args.interval)

    print("=" * 60)
    print(f"📊 Resumen Cliente {source_ip}: Exitosas: {success_count} | Bloqueadas: {blocked_count}")
    print("=" * 60)

if __name__ == "__main__":
    main()

