#!/usr/bin/env python3
"""
Simulador de Tráfico de Fondo Multi-Usuario (Navegación Continua en Vivo)
GOYS - TP4 Proyecto Integrador | UTN FR La Plata

Simula una comunidad de 5 a 10 usuarios legítimos concurrentes navegando el portal web
de forma indefinida con peticiones distribuidas, IPs y puertos efímeros dinámicos.
Permite demostrar en vivo que la IA no genera falsos positivos con tráfico nominal,
y que el bloqueo posterior de un atacante no interrumpe el servicio a usuarios reales.
"""

import sys
import time
import random
import signal
import argparse
import subprocess
import requests
from requests.adapters import HTTPAdapter

TARGET_BASE = "http://172.20.0.10"

VALID_PATHS = [
    "/",
    "/index.html",
    "/",
    "/index.html"
]

CLIENT_POOL = [
    {"ip": "172.20.0.51", "name": "Usuario-Chrome-Win", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"},
    {"ip": "172.20.0.52", "name": "Usuario-Firefox-Linux", "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"},
    {"ip": "172.20.0.53", "name": "Usuario-Safari-Mac", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"},
    {"ip": "172.20.0.54", "name": "Usuario-Edge-Win", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"},
    {"ip": "172.20.0.55", "name": "Usuario-Mobile-Android", "ua": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.80 Mobile Safari/537.36"}
]

class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_ip, **kwargs):
        self.source_ip = source_ip
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['source_address'] = (self.source_ip, 0)
        return super().init_poolmanager(*args, **kwargs)

def setup_client_ips():
    """Configura alias de IP dinámicos en eth0 para cada cliente del pool."""
    for client in CLIENT_POOL:
        try:
            subprocess.run(
                ["ip", "addr", "add", f"{client['ip']}/24", "dev", "eth0"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Simulador de Tráfico Legítimo Multi-Usuario Continuo")
    parser.add_argument("--rate", type=float, default=1.0, help="Intervalo promedio entre visitas en segundos (default: 1.0s)")
    parser.add_argument("--jitter", type=float, default=0.3, help="Variabilidad aleatoria en segundos (default: 0.3s)")
    args = parser.parse_args()

    setup_client_ips()

    # Manejo elegante de Ctrl+C
    running = True
    def signal_handler(sig, frame):
        nonlocal running
        print("\n[!] Deteniendo simulador de tráfico de fondo...")
        running = False
    signal.signal(signal.SIGINT, signal_handler)

    sessions = {}
    for client in CLIENT_POOL:
        s = requests.Session()
        try:
            adapter = SourceAddressAdapter(client["ip"])
            s.mount("http://", adapter)
        except Exception:
            pass
        sessions[client["ip"]] = s

    print("=" * 65)
    print("🌐 SIMULADOR DE TRÁFICO DE FONDO MULTI-USUARIO (MODO CONTINUO)")
    print(f"🎯 Servidor objetivo: {TARGET_BASE} (Nginx)")
    print(f"👥 Pool de clientes: {len(CLIENT_POOL)} usuarios simultáneos")
    for c in CLIENT_POOL:
        print(f"   ● {c['ip']} -> {c['name']}")
    print(f"⏱️ Frecuencia promedio: 1 petición cada {args.rate}s (±{args.jitter}s)")
    print("   Presioná Ctrl+C para finalizar la simulación.")
    print("=" * 65)

    request_count = 0
    start_wall_time = time.time()

    while running:
        client = random.choice(CLIENT_POOL)
        path = random.choice(VALID_PATHS)
        session = sessions.get(client["ip"], requests)

        headers = {
            "User-Agent": client["ua"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Connection": "close"  # Forzar cierre para asignar nuevo puerto efímero TCP en cada request
        }

        request_count += 1
        t_now = time.strftime("%H:%M:%S")

        try:
            t0 = time.time()
            res = session.get(f"{TARGET_BASE}{path}", headers=headers, timeout=2.5)
            elapsed_ms = round((time.time() - t0) * 1000, 1)

            if res.status_code == 200:
                print(f"[{t_now}] #{request_count:04d} | {client['ip']} ({client['name']}) -> GET {path:<11} [200 OK] {elapsed_ms}ms")
            else:
                print(f"[{t_now}] #{request_count:04d} | {client['ip']} -> GET {path:<11} [HTTP {res.status_code}]")
        except requests.exceptions.RequestException:
            print(f"[{t_now}] #{request_count:04d} | {client['ip']} -> GET {path:<11} [BLOQUEADO / TIMEOUT]")

        # Espera natural con jitter estocástico
        delay = max(0.2, args.rate + random.uniform(-args.jitter, args.jitter))
        time.sleep(delay)

    total_time = round(time.time() - start_wall_time, 1)
    print("=" * 65)
    print(f"🏁 Simulación concluida. Total peticiones: {request_count} en {total_time}s.")
    print("=" * 65)

if __name__ == "__main__":
    main()

