FROM python:3.11-alpine

# Instalamos utilidades de red básicas para pruebas de conectividad y multi-IP (ping, curl, netcat, iproute2)
RUN apk add --no-cache curl iputils bash netcat-openbsd iproute2

# Instalamos requests para los scripts de simulación de ataque y carga
RUN pip install --no-cache-dir requests

WORKDIR /scripts

# Mantenemos el contenedor vivo para poder ejecutar comandos interactivos o scripts
CMD ["tail", "-f", "/dev/null"]

