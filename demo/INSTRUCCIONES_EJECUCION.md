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

* El panel lateral izquierdo debe mostrar **ONLINE** para Nginx y el Nodo Atacante, y la etiqueta superior debe indicar **CENTINELA VIGILANDO**.
* En el panel central, el asistente confirmará la sincronización de la telemetría.

---

## 4. Paso 4: Ejecución de Ensayos y Pruebas de Ataque

Abrir una segunda ventana de terminal para simular el tráfico malicioso desde el contenedor `goys-attacker`.

### Ensayo A: Tráfico Legítimo y Conectividad Inicial
Verifica que el atacante tiene conectividad L3 (ICMP ping) y L7 (HTTP GET 200) contra el servidor Nginx:
```bash
docker exec -it goys-attacker bash /scripts/test_connectivity.sh
```

---

### Ensayo B: Ataque DoS Volumétrico (HTTP Flood)
Genera una ráfaga concurrente de 150 peticiones HTTP a la raíz `/` con User-Agent de bot:
```bash
docker exec -it goys-attacker python3 /scripts/dos_attack.py
```

**Resultado esperado en la Consola Web:**
1. El centinela conmuta a **AMENAZA ACTIVA**.
2. Llama 3.2 emite un reporte clasificando el incidente como **CRÍTICA / DoS Volumétrico**.
3. Se presenta el botón interactivo: `[ Aplicar política DROP para 172.20.0.99 ]`.
4. Al hacer clic en el botón:
   - Se inyecta la regla en la cadena `DOCKER-USER` del kernel Linux.
   - En el panel derecho de iptables aparece la regla activa.
   - Todo tráfico subsiguiente del atacante queda en estado `[BLOQUEADO / TIMEOUT]`.

---

### Ensayo C: Escaneo de Directorios y Fuerza Bruta L7
*(Si la IP 172.20.0.99 estaba bloqueada, presionar previamente "Revocar regla" en el panel de iptables).*

Dispara 24 solicitudes dirigidas hacia rutas administrativas y archivos sensibles (`/admin`, `/.env`, `/backup.sql`) con User-Agents de `DirBuster`:
```bash
docker exec -it goys-attacker python3 /scripts/bruteforce.py
```

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

