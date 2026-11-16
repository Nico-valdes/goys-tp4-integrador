# ChatOps & AIOps: Asistente Conversacional con LLM Local (Ollama) para Monitoreo de Red y Mitigación de Incidentes de Seguridad en Tiempo Real

> **Universidad Tecnológica Nacional — Facultad Regional La Plata**  
> **Cátedra:** Gestión Operativa y Seguridad en Redes (GOYS)  
> **Trabajo Práctico N.º 4:** Proyecto Integrador — Feria de Redes  
> **Modalidad:** A — Proyecto de Desarrollo  
> **Grupo:** Grupo 6  

---

## 👥 Integrantes y Asignación de Roles

| Integrante | Rol en el Proyecto | Responsabilidad Técnica Principal |
| :--- | :--- | :--- |
| **Nicolás Valdés** | Arquitectura & Backend AIOps | Coordinación general, diseño de arquitectura Two-Tier, motor de inferencia local con Ollama y despachador de telemetría |
| **Franco Pietrantuono** | Infraestructura & Redes | Virtualización en Docker bridge, servidor Nginx con logging enriquecido, patrón Sidecar de red y mitigación en kernel (`iptables`) |
| **Facundo Otero** | Seguridad & Análisis Forense | Modelado de amenazas L7 (DoS volumétrico y fuerza bruta), sockets dinámicos L3 (`SourceAddressAdapter`) y simulación de tráfico |
| **Ivan Vijandi** | Operaciones & Monitoreo | Interfaz de usuario ChatOps en tiempo real, observabilidad reactiva, procedimientos operativos y guías de ejecución |

---

## 📌 Descripción General

En centros de operaciones de red (NOC) y seguridad (SOC), el análisis manual de registros crudos (*logs*) introduce demoras críticas en el tiempo medio de contención (MTTR), mientras que los mecanismos de bloqueo estáticos tradicionales (como Fail2ban) carecen de contexto semántico, derivando en falsos positivos o denegaciones de servicio involuntarias sobre tráfico legítimo.

Este proyecto implementa una plataforma perimétrica de **ChatOps y AIOps** que unifica el monitoreo y la defensa activa de redes sobre contenedores Docker:
1. **Operación 100% Offline (On-Premise):** Emplea un modelo de lenguaje compacto (**Llama 3.2 3B**) ejecutado localmente mediante **Ollama**, garantizando privacidad absoluta de los registros corporativos sin fuga de telemetría hacia nubes públicas.
2. **Arquitectura Two-Tier (Determinista + Semántica):** La Capa 1 procesa estadísticas agregadas a velocidad de línea en Python (conteo de peticiones, códigos HTTP, ratios de concentración y User-Agents), mientras la Capa 2 sintetiza el dictamen forense y la severidad mediante inferencia del LLM en menos de 10 segundos.
3. **Control Human-in-the-Loop (HITL):** Ninguna regla de firewall es inyectada automáticamente a ciegas; el asistente conversacional expone la evidencia forense al operador y ofrece botones de acción directa para aplicar o revocar reglas `DROP` perimétricas.
4. **Mitigación a Nivel Kernel (Netfilter):** El servicio ChatOps comparte el namespace de red con el servidor web mediante el patrón **Sidecar**, inyectando políticas perimétricas en la cadena `INPUT`/`DOCKER-USER` de `iptables` antes de que los paquetes hostiles alcancen el socket de la aplicación.

---

## 🌐 Topología de Red Virtualizada

La red se despliega de forma autocontenida sobre un bridge virtual de Docker (`goys-net`):

```text
                      +---------------------------------------+
                      |    Docker Bridge Virtual: goys-net    |
                      |         Subred: 172.20.0.0/24         |
                      |         Gateway: 172.20.0.1           |
                      +-------------------+-------------------+
                                          |
             +----------------------------+----------------------------+
             |                                                         |
             v                                                         v
+---------------------------------------+             +---------------------------------+
|   goys-nginx-server                   |             |   goys-attacker                 |
|   IP: 172.20.0.10                     |             |   IP Base: 172.20.0.99          |
|   Puerto expuesto: 8080 (HTTP)        |             |   Aliases L3: .51-.55, .77, .88 |
|   Logging: $remote_addr + rt + $http_ua             |   Sockets dinámicos concurrentes|
|   +---------------------------------+ |             +---------------------------------+
|   | chatops-app (Sidecar)           | |                              |
|   | Comparte Network Namespace      | |                              |
|   | Acceso directo a iptables       | |                              v
|   | Puerto WebUI: 5000 (FastAPI)    | |             +---------------------------------+
|   +---------------------------------+ |             |   Tráfico Legítimo / Ataques    |
+---------------------------------------+             |   - DoS Volumétrico (HTTP Flood)|
                   |                                  |   - Fuerza Bruta y Escaneo L7   |
                   v                                  |   - 5 Clientes Normales (1 req/s|
+---------------------------------------+             +---------------------------------+
|   Ollama Local (Host / On-Premise)    |
|   Endpoint: http://localhost:11434    |
|   Modelo: llama3.2:3b                 |
+---------------------------------------+
```

### Tabla de Direccionamiento de Nodos

| Nodo | Contenedor | Dirección IP | Servicios / Puertos |
| :--- | :--- | :--- | :--- |
| **Gateway Virtual** | `bridge docker` | `172.20.0.1` | Ruteo inter-redes y gateway por defecto |
| **Servidor Web** | `goys-nginx` | `172.20.0.10` | Nginx HTTP en puerto 80 (mapeado a `8080`) |
| **Sidecar ChatOps** | `goys-chatops` | `172.20.0.10` *(shared ns)* | FastAPI / WebUI en puerto `5000`, interfaz iptables |
| **Nodo Atacante** | `goys-attacker` | `172.20.0.99` | Generador de tráfico L3/L7 y botnet sintética |
| **Clientes Legítimos** | *(aliases dinámicos)* | `172.20.0.51` - `.55` | Navegación nominal continua con User-Agents comerciales |
| **Vectores de Ataque** | *(aliases dinámicos)* | `172.20.0.77`, `.88`, `.120` | DoS volumétrico HTTP y escaneo DirBuster |

---

## 🚀 Puesta en Marcha Rápida (Offline Ready)

### 1. Requisitos Previos
- Docker Desktop en ejecución (con soporte para Linux Containers).
- Ollama instalado y en ejecución en el host:
  ```bash
  ollama run llama3.2:3b
  ```

### 2. Despliegue de la Infraestructura
Desde el directorio `demo/`:
```bash
docker compose up -d --build
```

### 3. Acceso a la Consola ChatOps
Abrir en el navegador web:
```text
http://localhost:5000
```

---

## 🛠️ Comandos de Operación en ChatOps

La consola conversacional permite monitorear y mitigar mediante lenguaje natural o comandos directos:

| Comando | Función Operativa |
| :--- | :--- |
| `/status` | Estado ICMP de Nginx y Gateway, velocidad de tráfico (req/s) y estado de Ollama |
| `/top` | Ranking de las 5 direcciones IP con mayor volumen y porcentaje de concentración |
| `/inspeccionar <IP>` | Perfil forense detallado de un origen: rutas visitadas, User-Agents y códigos HTTP |
| `/reglas` | Lista de políticas de filtrado perimetral activas en la cadena `DOCKER-USER` |
| `/bloquear <IP>` | Aplica regla `DROP` inmediata en el firewall de kernel para aislar una IP |
| `/desbloquear <IP>` | Remueve la regla de firewall y restablece la comunicación con el origen |
| `/reset` | Vacía los registros de acceso de Nginx (a 0) y purga las reglas de firewall |

---

## 🔬 Flujo de Demostración para la Feria de Redes

1. **Línea de Base (Tráfico Legítimo):**
   ```bash
   docker exec -it goys-attacker python3 /scripts/background_traffic.py
   ```
   *Resultado:* La consola web permanece en `CENTINELA VIGILANDO` (verde) con 0 alertas falsas y latencia < 2 ms.

2. **Detección de Escaneo L7 y Fuerza Bruta:**
   ```bash
   docker exec -it goys-attacker python3 /scripts/bruteforce.py --ip 172.20.0.120
   ```
   *Resultado:* El centinela detecta rutas críticas (`/admin`, `.env`, `/login`), Ollama clasifica como **Severidad ALTA** y se mitiga con un clic en **"Aplicar política DROP para 172.20.0.120"**.

3. **Detección de Ataque DoS Volumétrico (HTTP Flood):**
   ```bash
   docker exec -it goys-attacker python3 /scripts/dos_attack.py --ip 172.20.0.88 --requests 260
   ```
   *Resultado:* El centinela clasifica como **Severidad CRÍTICA** (260 peticiones masivas, User-Agent `AttackBot`), permitiendo el descarte perimétrico en kernel mientras los clientes legítimos continúan navegando sin interrupción.

4. **Escenario Multivector Concurrente (DDoS):**
   Lanzando ataques sucesivos desde IPs diferentes (`.77` y `.88`), el sistema gestiona los incidentes concurrentemente en cola, ofreciendo mitigación granular independiente para cada vector de la botnet.

---

## 📂 Estructura del Repositorio

```text
├── capturas/                     # Evidencias visuales de la WebUI y mitigación
├── demo/
│   ├── app/                      # Microservicio ChatOps & AIOps (FastAPI)
│   │   ├── core/                 # Motor de IA, parser de telemetría y firewall
│   │   └── static/               # Interfaz gráfica reactiva (HTML5/CSS3/Vanilla JS)
│   ├── attacker/                 # Contenedor generador de tráfico y ataques
│   ├── nginx/                    # Servidor web Nginx con configuración de logs
│   ├── scripts/                  # Scripts de ataque L3/L7 y tráfico nominal
│   └── docker-compose.yml        # Orquestación de contenedores y red bridge
├── diagramas/                    # Diagramas de arquitectura y topología de red
├── documento/                    # Documento final formal en Markdown y PDF
├── poster/                       # Plantilla A1 editable y versión lista para imprimir
├── progreso.md                   # Bitácora de avances y registro de hitos del equipo
└── README.md                     # Documentación principal del repositorio
```
