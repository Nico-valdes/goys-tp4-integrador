# 🚀 Guía de la Estación de Demo — TP4 GOYS

> **Proyecto:** ChatOps & AIOps con LLM Local para Mitigación de Incidentes en Tiempo Real  
> **Grupo 6:** Nicolás Valdés, Facundo Otero, Ivan Vijandi, Franco Pietrantuono  
> **Modalidad:** A — Proyecto de Desarrollo  

---

## 🏗️ 1. Topología de Red Virtual

El entorno de pruebas opera dentro de una red bridge virtual de Docker con direccionamiento IPv4 estático:

```text
               [ Docker Bridge: goys-net (172.20.0.0/24) ]
                   │ Gateway: 172.20.0.1
        ┌──────────┴──────────────┬─────────────────────────┐
        ▼                         ▼                         ▼
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│  Servidor    │          │    Nodo      │          │   Asistente  │
│    Nginx     │          │   Atacante   │          │   ChatOps    │
│ 172.20.0.10  │          │ 172.20.0.99  │          │ 172.20.0.20  │
└──────────────┘          └──────────────┘          └──────────────┘
```

| Contenedor | Dirección IP | Rol / Servicio | Puertos Expuestos |
|------------|--------------|----------------|-------------------|
| `goys-nginx` | `172.20.0.10` | Servidor Web de Producción con logs enriquecidos | `8080:80` (host) |
| `goys-attacker` | `172.20.0.99` | Nodo cliente/simulador de tráfico malicioso | - |
| `chatops-app` | `172.20.0.20` | Backend Python + WebUI + Conector Ollama | `5000:5000` (host) |

---

## ⚡ 2. Despliegue Rápido (100% Offline)

Asegurarse de tener Docker Desktop iniciado y ejecutar desde la carpeta `demo/`:

```bash
docker compose up -d --build
```

Para verificar que los contenedores estén corriendo:
```bash
docker ps
```

---

## 🧪 3. Pruebas y Scripts Disponibles

Todos los scripts de prueba residen en `demo/scripts/` y están montados dentro del contenedor `goys-attacker` en `/scripts`.

### A. Prueba de Conectividad (L3 + L7)
Valida que el atacante pueda alcanzar a Nginx tanto por ping (ICMP) como por petición web (HTTP 200):
```bash
docker exec -it goys-attacker bash /scripts/test_connectivity.sh
```

### B. Simulación de Ataque DoS Volumétrico
Dispara 150 peticiones HTTP concurrentes para saturar el servidor y generar anomalías de tráfico:
```bash
docker exec -it goys-attacker python3 /scripts/dos_attack.py
```

### C. Simulación de Fuerza Bruta / Escaneo de Directorios
Genera ráfagas de accesos hacia rutas no autorizadas (`/admin`, `/api/secret`, `/.env`) provocando respuestas `401 Unauthorized` y `403 Forbidden`:
```bash
docker exec -it goys-attacker python3 /scripts/bruteforce.py
```

---

## 📝 4. Observabilidad y Logs en Vivo

Los registros de Nginx se sincronizan automáticamente en tiempo real en la carpeta `demo/nginx/logs/access.log`.

Para visualizarlos en vivo:
```bash
docker logs -f goys-nginx
```
o bien abriendo el archivo local `demo/nginx/logs/access.log`.

