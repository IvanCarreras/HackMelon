# 🍉 HackMelon v1.1

**HackMelon** es una herramienta multifuncional de ciberseguridad ofensiva y defensiva escrita en Python. Permite realizar escaneos de red, análisis de puertos, fuzzing web, detección de XSS, consulta de CVEs, y más.

> ⚠️ Esta herramienta ha sido creada con fines educativos. Úsala únicamente en entornos controlados o con permiso explícito.

---

## 🧩 Funcionalidades actuales

| Módulo                       | Descripción |
|-----------------------------|-------------|
| 🔍 Escaneo de red (ARP)     | Identifica hosts activos en red local |
| 🔓 Escaneo de puertos (Nmap)| Escaneo TCP, UDP, sin ping, crítico |
| 🔎 Fuzzing web              | Descubre rutas/directorios ocultos |
| 💥 Scanner de XSS           | Detecta posibles inyecciones reflejadas |
| 📖 Consulta CVE             | Scrapea el CVE desde NVD |
| 🔧 Menú CLI                 | Interface sencilla por terminal |

---

## 📦 Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tuusuario/hackmelon.git
   cd hackmelon/src
   python3 main.py