#!/usr/bin/env python3
"""
Simulador de Escaneo y Fuerza Bruta HTTP
Envía peticiones continuas hacia endpoints protegidos o inexistentes (/admin, /login, /api/secret)
generando una alta tasa de códigos 401 Unauthorized y 404 Not Found.
"""

import time
import requests

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

def main():
    print("=" * 60)
    print(f"🕵️ INICIANDO ESCANEO DE RECONOCIMIENTO Y FUERZA BRUTA")
    print(f"🎯 Servidor objetivo: {TARGET_BASE}")
    print("=" * 60)

    for i in range(1, 25):
        endpoint = ENDPOINTS[i % len(ENDPOINTS)]
        url = f"{TARGET_BASE}{endpoint}"
        headers = {
            "User-Agent": f"DirBuster-Scanner/2.0-Attempt-{i}"
        }
        try:
            res = requests.get(url, headers=headers, timeout=2)
            print(f"[{i:02d}] GET {endpoint:<20} -> Código: {res.status_code}")
        except requests.exceptions.RequestException:
            print(f"[{i:02d}] GET {endpoint:<20} -> [BLOQUEADO / TIMEOUT]")
        time.sleep(0.15)

    print("=" * 60)
    print("✅ Escaneo completado. Logs enviados al servidor Nginx.")
    print("=" * 60)

if __name__ == "__main__":
    main()

