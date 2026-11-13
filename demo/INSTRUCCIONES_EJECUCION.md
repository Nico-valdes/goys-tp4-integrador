# Guía de Ejecución y Despliegue en Vivo — TP4 GOYS

Este documento detalla la secuencia ordenada de comandos para levantar la plataforma completa de **ChatOps & AIOps** de forma **100% offline**, ejecutar las simulaciones de ataque y validar la mitigación perimetral en tiempo real.

---

## 0. Prerrequisitos del Host

1. **Docker Desktop:** Iniciado y funcionando (motor Linux Containers).
2. **Ollama:** Instalado en el sistema operativo anfitrión.
3. **Modelo LLM local:** Verificar que `llama3.2:3b` esté descargado.

```bash
# Validar modelos disponibles en el host
ollama list
```
*(Si no está descargado previamente: `ollama pull llama3.2:3b`)*

---

## 1. Paso 1: Iniciar el Servicio de IA Local (Ollama)

Ollama debe estar escuchando en el puerto estándar `11434` del host para que el contenedor `chatops-app` se comunique vía `host.docker.internal`:

```bash
# Opción A: Si Ollama ya corre como servicio de fondo en Windows (ícono en la bandeja), no requiere comando adicional.

# Opción B: Si se inicia por terminal
ollama serve
```

Para verificar que la API local responde:
```bash
curl http://localhost:11434/api/tags
```

---

## 2. Paso 2: Levantar la Topología de Red en Docker

Desde una terminal situada en el directorio raíz del proyecto (`goys-tp4-integrador/`):

```bash
# Acceder a la carpeta demo
cd demo

# Construir imágenes e inicializar los 3 contenedores en red bridge
docker compose up -d --build
```

### Verificación de contenedores activos:
```bash
docker compose ps
```

Deben figurar los 3 servicios con estado `Up`:
* `goys-nginx` (IP: `172.20.0.10`, expuesto en `http://localhost:8080`)
* `goys-attacker` (IP: `172.20.0.99`)
* `chatops-app` (IP: `172.20.0.20`, expuesto en `http://localhost:5000`)

---

## 3. Paso 3: Acceder a la Consola de Operación ChatOps

Abrir el navegador web en:
```text
http://localhost:5000
```

* El panel lateral izquierdo debe mostrar **ONLINE** para Nginx y el Gateway, y la lista de orígenes en red aguardará el primer tráfico. La etiqueta superior indicará **CENTINELA VIGILANDO**.
* En el panel central, el asistente confirmará la sincronización de la telemetría.

---

## 4. Paso 4: Ejecución de Ensayos y Demostración Multi-Origen

Abrir una segunda ventana de terminal para interactuar con la red desde el simulador `goys-attacker`.

### Ensayo A: Tráfico de Fondo Multi-Usuario Continuo (Simulación en Vivo)
Simula un pool de 5 usuarios concurrentes navegando indefinidamente por el portal web desde IPs independientes (`172.20.0.51` a `172.20.0.55`) con navegadores comerciales (Chrome, Firefox, Safari, Edge, Android) a razón de ~1 petición por segundo con puertos efímeros dinámicos:
```bash
docker exec -it goys-attacker python3 /scripts/background_traffic.py
```

**Resultado esperado en la Consola Web:**
* En el panel lateral izquierdo, las 5 IPs de usuarios legítimos aparecen progresivamente con estado **PERMITIDO** en color verde.
* La telemetría suma peticiones continuas (~1 req/s) sin disparar alertas ni consumir inferencias en la GPU: el centinela permanece en estado **CENTINELA VIGILANDO**.
* Este script puede dejarse corriendo en una terminal en segundo plano durante toda la presentación.

---

### Ensayo B: Ataque DoS Volumétrico desde Origen Hostil (en Simultáneo)
Mientras el tráfico legítimo de fondo sigue corriendo en la Terminal 1, abrir una **Terminal 2** y disparar una ráfaga concurrente de 150 peticiones HTTP a la raíz `/` desde la IP atacante (`172.20.0.88`):
```bash
docker exec -it goys-attacker python3 /scripts/dos_attack.py --ip 172.20.0.88
```

**Resultado esperado en la Consola Web:**
1. El centinela conmuta automáticamente a **AMENAZA ACTIVA**.
2. Llama 3.2 discrimina entre el tráfico normal previo de `172.20.0.50` y la anomalía de `172.20.0.88`, clasificando el incidente como **CRÍTICA / DoS Volumétrico** y señalando como atacante a `172.20.0.88`.
3. Se presenta la acción Human-in-the-Loop: `[ Aplicar política DROP para 172.20.0.88 ]`.
4. Al hacer clic en el botón:
   - Se inyecta la regla perimetral en la cadena `DOCKER-USER` del kernel Linux.
   - En el panel de orígenes, el estado de `172.20.0.88` pasa inmediatamente a **BLOQUEADO (DROP)** en rojo.
   - Si se reintenta el ataque, todas las peticiones desde `172.20.0.88` quedan en `[BLOQUEADO / TIMEOUT]`.
5. **Verificación de Cero Falsos Positivos:** Al relanzar el cliente legítimo (`python3 /scripts/legitimate_traffic.py --ip 172.20.0.50`), sus peticiones continúan recibiendo **200 OK** sin interrupciones.

---

### Ensayo C: Escaneo de Directorios y Fuerza Bruta L7 desde Otra IP
Dispara un barrido hacia rutas administrativas y archivos sensibles (`/admin`, `/.env`, `/backup.sql`) con User-Agents de `DirBuster` desde una tercera IP (`172.20.0.120`):
```bash
docker exec -it goys-attacker python3 /scripts/bruteforce.py --ip 172.20.0.120
```

**Resultado esperado en la Consola Web:**
1. La telemetría detecta códigos `401 Unauthorized` y `404 Not Found`.
2. Llama 3.2 analiza la ráfaga activa, deduce el origen `172.20.0.120` y clasifica el incidente como **ALTA / Escaneo de rutas sensibles y fuerza bruta**.
3. Se ofrece la recomendación de mitigación específica para `172.20.0.120`.

**Resultado esperado en la Consola Web:**
1. La telemetría detecta múltiples códigos `401 Unauthorized` y `404 Not Found`.
2. Llama 3.2 reclasifica el incidente como **ALTA / Escaneo de rutas sensibles y fuerza bruta**.
3. Recomienda el bloqueo perimetral de la IP `172.20.0.99`.

---

## 5. Paso 5: Interacción Conversacional ChatOps

En la barra inferior de la consola web, se pueden ingresar comandos operativos o consultas libres:

* `$ /status` : Diagnóstico general de salud del clúster y métricas agregadas.
* `$ /reglas` : Listado de políticas de kernel activas.
* `$ /logs` : Visualización de las últimas peticiones registradas por Nginx.
* `$ /bloquear 172.20.0.99` : Inyección manual directa de regla DROP.
* `$ /desbloquear 172.20.0.99` : Remoción manual de la regla.
* **Consultas libres:** Preguntas técnicas al asistente (ej. *"¿Cómo funciona la cadena DOCKER-USER en iptables?"* o *"¿Qué IP generó mayor tráfico?"*).

---

## 6. Paso 6: Reseteo del Laboratorio

Para volver a dejar el entorno en cero (vaciar registros de acceso y purgar reglas de firewall) para una nueva demostración ante los docentes:

* **Opción Web:** Presionar el botón superior **↺ Resetear Lab** o escribir `/reset` en el chat.
* **Opción Terminal:**
```bash
docker exec -it chatops-app python3 -c "from core import telemetry, firewall; telemetry.clear_logs(); [firewall.unblock_ip(ip) for ip in list(firewall.BLOCKED_IPS.keys())]"
```

---

## 7. Paso 7: Detención Limpia del Entorno

Al finalizar la demostración o sesión de prueba:

```bash
cd demo
docker compose down
```
*(Para eliminar también volúmenes persistentes y empezar totalmente limpio en la próxima sesión: `docker compose down -v`)*

---

## 8. Diagnóstico de Problemas Frecuentes (Troubleshooting)

| Síntoma | Causa Probable | Solución |
|---|---|---|
| En la consola web, el modelo figura como `N/A` o desconectado. | Ollama no está corriendo en el host o el firewall de Windows bloquea el puerto 11434. | Ejecutar `ollama list` en el host y verificar que `curl http://localhost:11434/api/tags` retorne código 200. |
| El atacante no puede alcanzar a Nginx antes de iniciar los ataques. | La red virtual `goys-net` no se creó correctamente. | Ejecutar `docker network inspect goys-net` y validar que los 3 contenedores tengan asignadas las IPs `172.20.0.x`. |
| Error al aplicar regla DROP (`iptables: Operation not permitted`). | El contenedor `chatops-app` no tiene los privilegios de red requeridos. | Verificar en `demo/docker-compose.yml` la presencia de `cap_add: - NET_ADMIN`. |
| La consola web no actualiza el contador de peticiones. | El archivo `access.log` tiene bloqueo de lectura en Windows. | Reiniciar el contenedor ChatOps con `docker compose restart chatops-app`. |

