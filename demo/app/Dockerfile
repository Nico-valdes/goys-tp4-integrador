FROM python:3.11-alpine

# Herramientas del sistema para diagnóstico y manipulación de iptables
RUN apk add --no-cache iptables iputils curl bash

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# --reload permite que los cambios de código se apliquen en caliente sin reiniciar el contenedor
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000", "--reload"]
