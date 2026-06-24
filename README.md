# 🛡️ Sésamo Auditor

**Sésamo Auditor** es un framework modular y extensible para auditorías de seguridad web (DAST + SAST) con **25 plugins**, autenticación automática, post-explotación y reportes profesionales en PDF, Markdown y JSON.

---

## 🚀 Características

### 🔴 DAST (19 plugins — pruebas activas)
| Plugin | Vulnerabilidad |
|---|---|
| `sql_injection.py` | SQLi (error/time/boolean/login bypass) |
| `xss_scanner.py` | XSS Reflejado con canary tokens |
| `path_traversal.py` | Path Traversal / LFI |
| `ssrf_scanner.py` | SSRF a servicios internos + cloud metadata |
| `ssti_scanner.py` | SSTI (Jinja2, Twig, Freemarker, etc.) |
| `command_injection.py` | Command Injection en URLs, forms, headers |
| `nosql_injection.py` | NoSQL Injection MongoDB ($ne, $gt, $regex) |
| `log4shell.py` | Log4Shell CVE-2021-44228 |
| `jwt_attacks.py` | JWT alg:none, KID traversal, expiración |
| `csrf_scanner.py` | CSRF — tokens faltantes |
| `idor_scanner.py` | IDOR — IDs secuenciales |
| `mass_assignment.py` | Mass Assignment — campos extra |
| `open_redirect.py` | Open Redirect |
| `api_fuzzer.py` | Fuzzing de endpoints ocultos |
| `directory_listing.py` | Directory listing (/ftp/, /backup/) |
| `websocket_attacks.py` | WebSocket — inyección via WS |
| `race_condition.py` | Race Condition — peticiones concurrentes |
| `twofa_bypass.py` | 2FA Bypass — OTP débil, rate-limiting |
| `oauth_misconfig.py` | OAuth — state missing, redirect_uri |
| `nuclei_scanner.py` | Nuclei — miles de templates CVE |
| `post_exploitation.py` | Post-explotación con acceso admin |

### 🟠 SAST (6 plugins — análisis estático)
| Plugin | Análisis |
|---|---|
| `header_analyzer.py` | Headers de seguridad, CORS, cookies |
| `regex_leak_finder.py` | Secretos y credenciales en JS/HTML |
| `source_analyzer.py` | Source maps, .git, .env, backups |
| `sonarqube_scanner.py` | **SonarQube SAST** via API (código fuente) |

### 🤖 Automatización
- **Auth Engine**: SQLi login bypass, registro, JWT forgery — obtiene acceso admin automáticamente
- **Post-Exploitation**: extrae usuarios, tarjetas de crédito, quejas, direcciones, órdenes
- **SPA Detection**: detecta Single Page Applications y filtra falsos 200
- **Auth Filtering**: plugins no prueban endpoints que requieren autenticación sin token

### 📊 Reportes
- **PDF**: portada profesional, resumen ejecutivo con KPIs, hallazgos agrupados por severidad con KeepTogether (no se cortan entre páginas)
- **Markdown**: legible directamente en terminal
- **JSON**: estructura `metadata` + `resumen` + `hallazgos` + `plugins`
- **Dashboard Web**: Flask con gráficos Chart.js, filtros, paginación (dark mode)
- **Nomenclatura**: `{NombrePagina}_{fecha}.{ext}` en carpetas por página

---

## 🛠️ Instalación y Configuración

Sésamo Auditor se ejecuta dentro de un entorno virtualizado en Python para evitar conflictos con el gestor de paquetes de tu sistema operativo:

### 1. Descargar/clonar el proyecto y crear el entorno
Una vez descargada o clonada la carpeta del proyecto localmente, abre una terminal en el directorio del proyecto y ejecuta:
```bash
# Crear el entorno virtual
python3 -m venv venv
```

### 2. Activar el entorno virtual
- **En Linux/macOS**:
  ```bash
  source venv/bin/activate
  ```
- **En Windows**:
  ```cmd
  venv\Scripts\activate
  ```

### 3. Instalar dependencias base y Playwright
Instala las dependencias necesarias y configura el motor del navegador headless (Playwright) para el escaneo interactivo de SPAs y análisis dinámico de logs de consola (XSS):
```bash
pip install -r requirements.txt
pip install playwright
playwright install chromium
```

---

## ⚙️ Modos de Uso

Asegúrate de tener el entorno virtual activado (`source venv/bin/activate`) antes de ejecutar:

### Modo 1: Menú Interactivo
Si prefieres guiarte mediante opciones en terminal:
```bash
python main.py
```

### Modo 2: Línea de Comandos (CLI Directa)
Ideal para scripts, automatizaciones y escaneo directo de objetivos:
```bash
# Escaneo completo (Genera PDF con portada premium, JSON y Markdown)
python main.py --target http://localhost:3000 --formato all

# Generar un formato específico de reporte
python main.py --target http://localhost:3000 --formato pdf
python main.py --target http://localhost:3000 --formato json
python main.py --target http://localhost:3000 --formato markdown
```

### Modo 3: Visualización en Dashboard Web
Inicia la consola visual interactiva basada en Flask:
```bash
python main.py --target http://localhost:3000 --formato dashboard
```

---

## 📁 Estructura

```
├── core/               → Engine, crawler, http_client, interfaces, modelos, logger
├── plugins/dast/       → 19 plugins DAST (auto-descubiertos)
├── plugins/sast/       → 6 plugins SAST (auto-descubiertos)
├── integraciones/      → Auth engine, Playwright crawler
├── wordlists/          → 12 archivos de payloads
├── reportes/           → Generadores PDF, Markdown, JSON
├── dashboard/          → Flask web dashboard
├── tests/              → 28 tests (pytest)
├── config.json         → Configuración central
├── main.py             → CLI entry point
└── requirements.txt    → Dependencias
```

---

## ⚙️ Configuración (`config.json`)

El archivo [config.json](file:///home/joao_moreira/Vídeos/Sesamo-Auditor/config.json) es el archivo central de configuración de Sésamo Auditor. Permite personalizar el comportamiento de los escaneos sin modificar el código fuente:

* **`target`**:
  * `url`: La dirección base de la aplicación web a auditar (ej. `http://localhost:3000`).
  * `exclusiones`: Lista de rutas URL que el crawler no debe visitar bajo ningún concepto (como `/logout` para no perder sesiones, o canales WebSocket como `/socket.io`).
* **`crawler`**: Configura la profundidad (`max_depth`), cantidad máxima de URLs a escanear (`max_urls`) y workers simultáneos.
  * `headless`: Opciones para habilitar Playwright durante el crawling de SPAs (React, Vue, Angular).
* **`http_client`**: Ajusta el tiempo de espera (`timeout_segundos`), rate limiting (`rate_limit_delay` en segundos) y reintentos automáticos para evitar ser bloqueados por el servidor o WAF.
* **`plugins`**:
  * `habilitar_dast` / `habilitar_sast`: Habilitan o deshabilitan las pruebas dinámicas o estáticas respectivamente.
  * `alert_threshold`: Umbral de alerta (`OFF`, `LOW`, `MEDIUM`, `HIGH`). En `HIGH`, el motor descarta hallazgos no confirmados (`Tentativa`).
* **`sonarqube`**: Configuración para importar vulnerabilidades de SonarQube.
* **`reportes`**: Define el formato de exportación por defecto y la ruta de salida.
* **`logging`**: Configuración del logger para la terminal y archivos físicos de registro.

---

## 🔌 Integración con SonarQube

Sésamo Auditor puede consultar issues de seguridad de SonarQube Server o SonarCloud a través de su API para incluirlos en el reporte consolidado.

### Configuración en `config.json`:
```json
"sonarqube": {
    "habilitar": true, // Cambiar a true para activar la integración
    "url": "https://sonarcloud.io", // Servidor SonarQube o SonarCloud
    "token": "squ_tu_token_aqui", // Token de acceso API generado en tu cuenta Sonar
    "project_key": "mi-organizacion_mi-proyecto" // Clave del proyecto en SonarQube
}
```

### Automatizar con GitHub Actions:
```yaml
# .github/workflows/sonar.yml
name: SonarQube Scan
on: [push]
jobs:
  sonar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

```properties
# sonar-project.properties (raíz del proyecto)
sonar.projectKey=tu_usuario_tu_proyecto
sonar.organization=tu_usuario
sonar.host.url=https://sonarcloud.io
```

---

## 📂 Output

Los reportes se guardan en `reportes_output/{NombrePagina}/`:

```
reportes_output/
└── OWASP_Juice_Shop/
    ├── OWASP_Juice_Shop_2026-06-18.json
    ├── OWASP_Juice_Shop_2026-06-18.md
    └── OWASP_Juice_Shop_2026-06-18.pdf
```

El nombre se extrae automáticamente del `<title>` de la página.

---

## 🧪 Tests

```bash
pytest tests/ -v
```

---

## 📄 Licencia

MIT
