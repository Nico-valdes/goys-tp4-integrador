#!/bin/bash
# ==============================================================
# Script de Verificación de Conectividad (L3 y L7)
# Ejecutado desde el nodo atacante / cliente (172.20.0.99)
# ==============================================================

TARGET_IP="172.20.0.10"
TARGET_PORT="80"

echo "============================================="
echo "🔍 1. Verificando conectividad L3 (ICMP / Ping)..."
echo "============================================="
ping -c 3 $TARGET_IP

if [ $? -eq 0 ]; then
    echo "✅ Conectividad Capa 3: OK (El host $TARGET_IP responde)"
else
    echo "❌ Error en Capa 3: No se pudo hacer ping a $TARGET_IP"
fi

echo ""
echo "============================================="
echo "🌐 2. Verificando conectividad L7 (HTTP / curl)..."
echo "============================================="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://$TARGET_IP:$TARGET_PORT/)

if [ "$HTTP_CODE" == "200" ]; then
    echo "✅ Conectividad Capa 7: OK (HTTP 200 recibido desde $TARGET_IP)"
    curl -s http://$TARGET_IP:$TARGET_PORT/ | grep -o "<title>.*</title>"
else
    echo "❌ Conectividad Capa 7: Falló o bloqueado (Código HTTP: $HTTP_CODE)"
fi
echo "============================================="

