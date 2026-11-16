# Bitácora del grupo — TP4

> Registro de avance, asignación de roles, arquitectura y decisiones técnicas del Grupo 6.

---

## 👥 Integrantes y Roles

| Nombre | Rol en el grupo | Responsabilidad Principal |
|--------|-----------------|---------------------------|
| **Nicolás Valdés** | Arquitectura & Backend ChatOps | Diseño general de la solución, backend en Python, integración con Ollama y orquestación de la mitigación |
| **Franco Pietrantuono** | Infraestructura & Redes | Topología virtual en Docker, servidor Nginx, configuración de red L2/L3 y reglas de firewall (iptables) |
| **Facundo Otero** | Seguridad & Análisis de Incidentes | Modelado de amenazas, ingeniería de prompts para análisis forense y scripts de prueba de ataques (DoS y fuerza bruta) |
| **Ivan Vijandi** | Operaciones & Monitoreo | Interfaz web de usuario (WebUI), recolección de telemetría de contenedores y observabilidad de servicios |

---

## 🎯 Definición del Proyecto

- **Modalidad:** **A — Proyecto de Desarrollo**
- **Título:** *ChatOps & AIOps: Asistente Conversacional con LLM Local (Ollama) para Monitoreo de Red y Mitigación de Incidentes de Seguridad en Tiempo Real*
- **Problema / Justificación:**
  En infraestructuras de red, el monitoreo continuo y el análisis forense de registros crudos (*logs*) demanda tiempo y pericia técnica, retrasando la contención de incidentes. Los bloqueos estáticos tradicionales (como Fail2ban) carecen de análisis contextual y pueden derivar en falsos positivos aislando tráfico legítimo.
- **Objetivo:**
  Implementar una plataforma liviana de **ChatOps y AIOps** sobre contenedores en red virtualizada, que centralice la telemetría de servicios, interprete incidentes de seguridad mediante un Modelo de Lenguaje on-premise (**Ollama**) bajo el paradigma **"Human-in-the-Loop"**, y permita mitigar amenazas en el firewall perimetral (`iptables`) en tiempo real, operando de forma **100% offline**.

---

## 🏗️ Cobertura de las 3 Áreas Obligatorias

| Área | Implementación Concreta en el Proyecto |
|---|---|
| 🔌 **Redes** | Topología virtualizada en red bridge Docker (`172.20.0.0/24`), servidor web Nginx (`172.20.0.10`), nodo cliente/atacante (`172.20.0.99`), puertos TCP (80/HTTP) y reglas de filtrado perimetral del kernel (`iptables DROP/ACCEPT`). |
| ⚙️ **Operación (Gestión)** | Automatización mediante **ChatOps**: consulta de disponibilidad (/status), sondeo periódico de latencia/pings, inspección de consumo de recursos y ejecución de acciones correctivas sin requerir acceso SSH directo. |
| 🛡️ **Seguridad (+ IA)** | Detección de patrones anómalos (DoS volumétrico y fuerza bruta), análisis semántico de logs y clasificación de riesgo mediante un LLM local (**Ollama**), garantizando privacidad de datos de red y mitigación activa. |

---

## 💻 Garantía de Operación en la Feria

El proyecto está diseñado para funcionar **100% OFFLINE** en la laptop del grupo:
- Stack de servicios virtualizados en contenedores Docker locales.
- Modelo de lenguaje ejecutado localmente con Ollama (sin llamadas a APIs en la nube).
- Interfaz web local de ChatOps accesible en `http://localhost:5000` (con fallback opcional a bot de Telegram si hubiera conectividad).

---

## 🗓️ Registro de Avance

| Fecha | Hito / Tarea | Responsable | Estado |
|-------|--------------|-------------|--------|
| 10/11/2026 | Definición de modalidad (A) y alcance del proyecto | Todos | ✅ Completado |
| 10/11/2026 | Asignación formal de roles para los 4 integrantes | Todos | ✅ Completado |
| 10/11/2026 | Envío de propuesta técnica a la cátedra para validación | Grupo 6 | ✅ Completado |
| 11/11/2026 | Construcción de la topología virtual (`docker-compose.yml`), red bridge (`172.20.0.0/24`), servidor Nginx con logging forense y nodo atacante con scripts L3/L7 | Franco Pietrantuono | ✅ Completado |
| 11/11/2026 | Desarrollo del backend de ChatOps (FastAPI), parser de telemetría de Nginx, gestor de firewall y comandos operativos (/status, /bloquear, /desbloquear, /reglas) | Nicolás Valdés | ✅ Completado |
| 11/11/2026 | Integración del motor AIOps con LLM local (Ollama / qwen2.5:1.5b), prompt engineering para análisis forense de logs y flujo interactivo Human-in-the-Loop | Nicolás Valdés | ✅ Completado |
| 12/11/2026 | Implementación de patrón Sidecar Network (`network_mode: service:nginx-server`) con `NET_ADMIN`, arquitectura Two-Tier AIOps (preprocesamiento determinista + inferencia contextual con Llama 3.2 3B) y consola reactiva WebUI | Franco Pietrantuono & Ivan Vijandi | ✅ Completado |
| 13/11/2026 | Resolución de concurrencia multi-incidente (cola FIFO, ventana de 300 eventos, deduplicación y filtros léxicos contra loops de Ollama), ensayos de DoS/fuerza bruta multi-IP y verificación de tráfico legítimo aislado | Facundo Otero & Nicolás Valdés | ✅ Completado |
| 14/11/2026 | Redacción integral del documento técnico (`documento/documento-final.md`), diseño y renderizado de topología SVG (`diagramas/topologia-red.svg`) y actualización de README | Todos | ✅ Completado |
| 15/11/2026 | Compilación del documento técnico a PDF con maquetación académica y diseño del póster A1 interactivo en HTML | Todos | ✅ Completado |
| 16/11/2026 | Compilación de póster A1 a PDF alta resolución (`poster/poster-A1.pdf`), organización de capturas de evidencia y validación de checklist de entrega | Todos | ✅ Completado |

---

## 🚧 Próximos Pasos

- [x] Definir tema definitivo y alcance del proyecto
- [x] Elegir modalidad (A — Proyecto de Desarrollo)
- [x] Asignar roles a los 4 integrantes
- [x] Construcción de la topología virtual (`docker-compose.yml`)
- [x] Implementación del backend ChatOps y telemetría de red
- [x] Conexión del motor AIOps con la API local de Ollama e interacción Human-in-the-Loop
- [x] Visto bueno y validación de propuesta técnica
- [x] Ejecución de escenarios de ataque y captura de evidencias (Fase 5)
- [x] Redacción del documento técnico final en `documento/`
- [x] Maquetación y exportación del póster A1 en `poster/`
- [x] Validación completa contra `templates/checklist-entrega.md`
