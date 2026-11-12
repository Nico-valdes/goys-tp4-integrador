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

> Para una guía paso a paso detallada con todos los ensayos y comandos de mitigación, consultar [INSTRUCCIONES_EJECUCION.md](INSTRUCCIONES_EJECUCION.md).

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

---

## 🧠 5. Entrenamiento y Adaptación del Modelo (AIOps Two-Tier)

En ciberseguridad, inyectar miles de registros crudos directamente a un LLM satura la ventana de contexto y eleva la latencia a niveles inaceptables. Este proyecto implementa una arquitectura **Two-Tier (Dos Niveles)** asistida por **In-Context Learning (ICL)**:

1. **Capa 1: Preprocesamiento Determinista de Alta Velocidad (Python):**
   - Agrega hasta 100.000 logs en microsegundos usando contadores eficientes.
   - Aplica una **ventana deslizante activa** (Sliding Window) para aislar ráfagas recientes de tráfico sin contaminación de eventos pasados.
   - Genera una ficha estadística estructurada en JSON (~15 líneas) con distribución de códigos HTTP, IPs dominantes, User-Agents y rutas protegidas.
2. **Capa 2: Inferencia Semántica y Razonamiento Contextual (Llama 3.2 3B):**
   - Consume un *System Prompt* estricto con taxonomía de severidad (estilo CVSS/SOC: Crítica, Alta, Media, Baja).
   - Analiza la intencionalidad del tráfico, deduciendo en 3 a 4 segundos el vector hostil y recomendando la regla perimetral exacta.
   - **Ventaja sobre Fine-Tuning:** Evita el sobreajuste (*overfitting*) a formatos rígidos y permite actualizar la ontología de amenazas al instante sin costosos reentrenamientos de pesos.

---

## 🧪 6. Protocolo de Pruebas y Validación Empírica

| Ensayo | Script | Vector Evaluado | Resultado Verificado |
|---|---|---|---|
| **E1: Conectividad Nominal** | `test_connectivity.sh` | Conectividad L3 (ICMP) y L7 (HTTP) | Respuestas 200 OK, latencia < 5ms, centinela vigilando. |
| **E2: DoS Volumétrico** | `dos_attack.py` | 150 peticiones HTTP concurrentes a `/` | Alerta CRÍTICA automática, corte inmediato tras inyección DROP. |
| **E3: Escaneo y Fuerza Bruta** | `bruteforce.py` | 24 solicitudes a endpoints protegidos (`/admin`, `/.env`) | Detección de errores 401/404, alerta ALTA, recomendación DROP. |
| **E4: Transición Bidireccional** | Secuencia E2 → E3 y E3 → E2 | Ráfagas sucesivas sin reseteo de logs | Clasificación correcta de cada vector sin falsos positivos. |

* **Latencia de inferencia local (Llama 3.2):** ~3.800 ms promedio.
* **Tiempo de inserción en kernel (iptables):** < 8 ms desde la confirmación del operador.
* **Tasa de mitigación:** 100% de los paquetes descartados a nivel de Netfilter.

---

## 🛡️ 7. Seguridad y Resiliencia del Sistema

* **Paradigma Human-in-the-Loop (HITL):** El modelo de IA actúa como asesor analítico y jamás ejecuta comandos arbitrarios sin aprobación. El operador humano debe validar explícitamente la acción (`Aplicar política DROP`).
* **Protección contra Prompt Injection:** El User-Agent y los datos de logs no son evaluados como código. La IP objetivo se extrae y valida estrictamente mediante expresiones regulares IPv4.
* **Listas Blancas Automáticas:** El sistema descarta automáticamente IPs críticas de infraestructura (`127.0.0.1`, `172.20.0.10`, `172.20.0.1`) previniendo ataques de denegación de servicio auto-infligidos por *spoofing*.
* **Filtrado en Cadena DOCKER-USER:** Las reglas se inyectan en la cadena `DOCKER-USER`, evaluándose antes del reenvío NAT de Docker y descartando paquetes en el nivel más bajo del kernel.
* **Privacidad 100% On-Premise:** Los registros corporativos y datos de red jamás abandonan la máquina local hacia APIs cloud externas.

---

## 🏢 8. Escalabilidad a una Infraestructura de Tipo Enterprise

Para migrar esta arquitectura desde la estación de demostración local hacia un entorno corporativo de escala masiva:

```text
[Tráfico de Borde] ──> [Ingress K8s (Envoy/Nginx)] ──> [Fluent Bit / Vector]
                                                               │
                                                               ▼ (Streaming de logs)
                                                    [Apache Kafka / Redpanda]
                                                               │
                                                               ▼
                                                  [Motor AIOps Distribuido]
                                                               │
                                     ┌─────────────────────────┴────────────────────────┐
                                     ▼                                                  ▼
                       [vLLM / Triton Inference Pool]                    [Mitigación Perimetral Distribuida]
                       - Servidores GPU (A100 / H100)                    - Filtrado en Kernel eBPF (Cilium)
                       - Batching dinámico (< 400ms)                     - Actualización dinámica en Cloud WAF
                       - Colas asíncronas (RabbitMQ/Redis)               - Anuncio BGP Flowspec a routers de borde
```

1. **Ingesta de Streaming Distribuido:**
   - Reemplazo de archivos locales por agentes ultralivianos (**Fluent Bit** o **Vector**) como *DaemonSets* en Kubernetes.
   - Buffer masivo mediante clúster distribuido de **Apache Kafka** capaz de procesar más de 1.000.000 de eventos/segundo hacia **OpenSearch**.
2. **Inferencia LLM de Alto Rendimiento:**
   - Despliegue de clústeres de inferencia con **vLLM** o **Triton Inference Server** sobre pools de aceleradores GPU con paralelismo de tensores, reduciendo la latencia a menos de 400 ms.
   - Desacoplamiento de tareas mediante colas de mensajes (**RabbitMQ** / **Redis**).
3. **Mitigación Perimetral Distribuida:**
   - **Kernel eBPF (Cilium):** Descarte de paquetes en el controlador de red (*XDP*) a velocidad de línea (40 Gbps+) sin costo de CPU en el stack TCP/IP.
   - **Integración con Cloud WAF:** Sincronización automática de listas negras en **Cloudflare WAF** o **AWS Network Firewall**.
   - **BGP Flowspec (RFC 5575):** Para ataques masivos de saturación de enlaces, propagación de reglas de descarte directamente a los routers del proveedor de tránsito (ISP).


