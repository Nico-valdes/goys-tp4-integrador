# Bitácora del grupo — TP4

> Registro de avance, asignación de roles, arquitectura y decisiones técnicas del Grupo 6.

---

## 👥 Integrantes y Roles

| Nombre | Rol en el grupo | Responsabilidad Principal |
|--------|-----------------|---------------------------|
| **Nicolás Valdés** | Coordinador / Arquitectura | Definición de ChatOps, formulación del problema y presentación |
| **Facundo Otero** | Módulo de Inteligencia Artificial | Integración con Ollama, prompt engineering y análisis de incidentes |
| **Ivan Vijandi** | Operaciones & Automatización | Backend en Python, recolección de telemetría y orquestación Docker |
| **Franco Pietrantuono** | Infraestructura & Redes | Topología virtual en Docker, servidor Nginx y reglas de Firewall (iptables) |

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
| 10/11/2026 | Envío de propuesta técnica a la cátedra para validación | Grupo 6 | 🟡 En espera de feedback |

---

## 🚧 Próximos Pasos

- [x] Definir tema definitivo y alcance del proyecto
- [x] Elegir modalidad (A — Proyecto de Desarrollo)
- [x] Asignar roles a los 4 integrantes
- [ ] Visto bueno de la cátedra (@ofalabel / @rodriguezemautn)
- [ ] Construcción de la topología virtual (`docker-compose.yml`)
- [ ] Implementación del backend ChatOps y conexión con la API local de Ollama
- [ ] Redacción del borrador del documento técnico (5-7 págs) en `documento/`
- [ ] Maquetación del póster A1 en `poster/`
