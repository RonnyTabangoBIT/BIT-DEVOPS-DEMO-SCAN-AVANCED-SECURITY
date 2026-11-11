# Investigación: GitHub Advanced Security

Este documento reúne lo investigado sobre:

1. El uso de **GitHub Advanced Security (GHAS)**.
2. Cómo **generar y publicar reportes en PDF** desde un **workflow centralizado**.
3. Qué hace falta para tener un mecanismo de **excepción, exclusión o control mínimo** de vulnerabilidades de dependencias en GitHub Actions.
4. **Copilot Autofix**: cómo funciona, cómo se usa, qué alcance tiene y en qué casos sirve.

> Las funcionalidades, licencias y precios de GitHub cambian seguido. Antes de tomar decisiones de compra o arquitectura, conviene revisar las [referencias](#5-referencias) oficiales.

---

## Índice

- [1. GitHub Advanced Security](#1-github-advanced-security)
- [2. Reportes PDF desde un workflow centralizado](#2-reportes-pdf-desde-un-workflow-centralizado)
- [3. Excepción, exclusión y control mínimo de vulnerabilidades de dependencias](#3-excepción-exclusión-y-control-mínimo-de-vulnerabilidades-de-dependencias)
- [4. Copilot Autofix](#4-copilot-autofix)
- [5. Referencias](#5-referencias)

---

## 1. GitHub Advanced Security

### 1.1 Qué es y cómo se licencia

GHAS es el conjunto de funciones de seguridad que GitHub integra en el repositorio, los Pull Requests y GitHub Actions. Desde abril de 2025 se vende como **dos productos separados**, que se pueden comprar por separado (también en el plan **GitHub Team**):

| Producto | Incluye | Precio de referencia |
|---|---|---|
| **GitHub Secret Protection** | Secret scanning, push protection, patrones personalizados, Copilot secret scanning (contraseñas genéricas), bypass delegado, security overview | ~USD 19 por committer activo al mes |
| **GitHub Code Security** | Code scanning (CodeQL y herramientas de terceros), **Copilot Autofix**, Dependency review, reglas personalizadas de Dependabot (auto-triage), security campaigns, security overview | ~USD 30 por committer activo al mes |

- En **repositorios públicos**, la mayoría de estas funciones son **gratuitas**: code scanning, secret scanning, push protection, dependency review y Autofix.
- Varias funciones son **gratuitas en cualquier repositorio**: dependency graph, Dependabot alerts, Dependabot security updates y version updates.
- Se cobra por **committer activo único**, es decir, cada usuario que hizo push en los últimos 90 días a un repositorio que tiene la función habilitada.

### 1.2 Componentes principales

| Componente | Qué hace | Dónde se ve |
|---|---|---|
| **Dependency graph** | Arma el inventario de dependencias a partir de los manifiestos (`requirements.txt`, `package.json`, workflows de Actions, etc.) y puede exportar un SBOM en formato SPDX | Insights → Dependency graph |
| **Dependabot alerts** | Avisa cuando una dependencia está afectada por un advisory de la GitHub Advisory Database | Security → Dependabot |
| **Dependabot security / version updates** | Abre PRs que actualizan dependencias vulnerables o desactualizadas (`.github/dependabot.yml`) | Pull requests |
| **Dependency review** | Compara las dependencias entre dos commits o en un PR y bloquea si se agregan dependencias vulnerables o con licencias no permitidas (`actions/dependency-review-action`) | PR / Actions |
| **Code scanning (CodeQL)** | Análisis estático (SAST) del código y de los workflows de Actions; acepta SARIF de herramientas de terceros | Security → Code scanning |
| **Copilot Autofix** | Propone correcciones generadas con IA para las alertas de code scanning | PR / alerta |
| **Secret scanning + Push protection** | Detecta secretos en el código y el historial, y bloquea el push antes de que el secreto entre al repositorio | Security → Secret scanning |
| **Security overview** | Vista de riesgo y cobertura a nivel organización o enterprise, con exportación a CSV | Org → Security |
| **Security campaigns** | Campañas para remediar alertas en lote, con fecha límite y responsables | Org → Security → Campaigns |
| **Security configurations** | Plantillas que habilitan las funciones de forma masiva en los repositorios de la organización | Org → Settings → Code security |

### 1.3 Formas de habilitar code scanning

- **Default setup**: GitHub detecta los lenguajes y ejecuta CodeQL solo, sin agregar un YAML al repositorio. Es la opción recomendada para empezar a gran escala.
- **Advanced setup**: un workflow propio con `github/codeql-action`, como el [workflow de este repo](.github/workflows/advanced-security.yml). Permite elegir query suites (`security-extended`, `security-and-quality`), una matriz de lenguajes, modos de build y categorías de SARIF.
- **Herramientas de terceros**: cualquier herramienta que genere SARIF (Trivy, Semgrep, Checkmarx, etc.) se puede subir con `github/codeql-action/upload-sarif`.

### 1.4 Cómo hacer obligatorios los controles a nivel organización

| Mecanismo | Uso |
|---|---|
| **Security configurations** | Habilitan dependency graph, Dependabot, code scanning y secret scanning en todos los repositorios o en un subconjunto |
| **Rulesets: "Require code scanning results"** | Bloquea el merge si hay alertas de code scanning por encima de un umbral (por ejemplo, `High or higher`) |
| **Rulesets: "Require workflows to pass before merging"** | Obliga a ejecutar un workflow que vive en un **repositorio central** (por ejemplo, el de dependency review) en todos los repositorios elegidos, sin que cada equipo tenga que copiarlo |
| **Políticas de Actions** | Lista de acciones permitidas y exigencia de fijar acciones por SHA, a nivel organización o enterprise |
| **Delegated bypass / delegated alert dismissal** | Exige que un revisor apruebe antes de saltarse push protection o descartar alertas |

### 1.5 Relación con este repositorio demo

| Función | Estado en este repo |
|---|---|
| CodeQL (Python + Actions) | ✅ Job `codeql`, advanced setup con `security-extended` |
| Dependency review | ✅ Job `dependency-review` con `fail-on-severity: moderate` |
| Dependabot | ✅ `.github/dependabot.yml` (pip + github-actions) |
| Secret scanning / Push protection | ⚙️ Se habilita en Settings, no requiere workflow |
| Reportes PDF centralizados | ❌ Pendiente (ver sección 2) |
| Excepciones de dependencias | ❌ Pendiente (ver sección 3) |

---

## 2. Reportes PDF desde un workflow centralizado

### 2.1 Punto de partida

GitHub **no genera PDFs de los hallazgos de seguridad de forma nativa**. Lo que ofrece es:

- La exportación a **CSV** desde Security overview, que es manual y se hace desde la interfaz.
- Los archivos **SARIF** que generan CodeQL y otras herramientas.
- La **API REST/GraphQL** de alertas, a nivel repositorio, organización y enterprise.
- El **SBOM** (SPDX) del dependency graph.

Por lo tanto, el PDF se tiene que generar en un workflow: se obtienen los datos por API, se renderiza HTML y se convierte a PDF.

### 2.2 Arquitectura propuesta

```text
┌────────────────────────── repo central: org/security-workflows ──────────────────────────┐
│                                                                                           │
│  .github/workflows/security-report.yml   (on: schedule | workflow_dispatch | workflow_call)│
│        │                                                                                  │
│        ├─ 1. Token de GitHub App (permisos de solo lectura sobre alertas)                 │
│        ├─ 2. Script: consulta APIs de la org  ──►  code-scanning / dependabot / secrets   │
│        ├─ 3. Plantilla HTML (Jinja2) + CSS corporativo                                    │
│        ├─ 4. HTML ──► PDF (WeasyPrint)                                                    │
│        └─ 5. Publicación: artifact │ release │ Teams/Slack/email │ Blob/S3/SharePoint     │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
          ▲                                        ▲
          │ workflow_call (reporte por repo)       │ schedule (reporte consolidado de la org)
   repo-app-1, repo-app-2, ...               cron semanal/mensual
```

Hay dos modalidades:

1. **Reporte consolidado de la organización**: corre por `schedule` en el repositorio central y consulta los endpoints de la organización (`/orgs/{org}/...`). Ningún repositorio de aplicación tiene que hacer nada.
2. **Reporte por repositorio**: cada repositorio llama al workflow reutilizable con `workflow_call`, por ejemplo al final del pipeline de `main` o en cada release. Si se quiere que sea obligatorio, se exige con un ruleset de tipo *Require workflows*.

### 2.3 Requisitos

| Requisito | Detalle |
|---|---|
| Repositorio central | Por ejemplo, `org/security-workflows`. En *Settings → Actions → General → Access* hay que permitir el acceso desde los repositorios de la organización |
| **GitHub App** (recomendado) | Permisos de **lectura**: `Code scanning alerts`, `Dependabot alerts`, `Secret scanning alerts`, `Metadata`, y `Administration: read` si se necesita listar repositorios. Instalada en la organización. El `app-id` y la `private-key` se guardan como secretos de la organización |
| Por qué no usar `GITHUB_TOKEN` | Solo tiene acceso al repositorio donde corre el workflow y **no puede leer las alertas de la organización** ni, en general, las de Dependabot |
| Licencia | Code Security y Secret Protection en los repositorios privados que se quieran incluir |
| Runner | `ubuntu-latest` alcanza: WeasyPrint se instala con pip y necesita las librerías Pango, que ya vienen en la imagen |

### 2.4 Endpoints de la API que se usan

| Dato | Organización | Repositorio |
|---|---|---|
| Code scanning | `GET /orgs/{org}/code-scanning/alerts` | `GET /repos/{owner}/{repo}/code-scanning/alerts` |
| Dependabot | `GET /orgs/{org}/dependabot/alerts` | `GET /repos/{owner}/{repo}/dependabot/alerts` |
| Secret scanning | `GET /orgs/{org}/secret-scanning/alerts` | `GET /repos/{owner}/{repo}/secret-scanning/alerts` |
| SBOM | — | `GET /repos/{owner}/{repo}/dependency-graph/sbom` |

Todos aceptan filtros como `state=open`, `severity=critical,high` y `per_page=100`, y devuelven resultados paginados mediante el header `Link`.

### 2.5 Workflow reutilizable de ejemplo (repositorio central)

```yaml
# org/security-workflows/.github/workflows/security-report.yml
name: Security Report (PDF)

on:
  schedule:
    - cron: "0 12 * * 1"          # lunes 12:00 UTC: reporte consolidado
  workflow_dispatch:
  workflow_call:                   # reporte por repositorio
    inputs:
      repository:
        description: "owner/repo; vacío = toda la organización"
        type: string
        default: ""
    secrets:
      REPORT_APP_ID:
        required: true
      REPORT_APP_KEY:
        required: true

permissions:
  contents: read

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout del repo central (script + plantilla)
        uses: actions/checkout@v4
        with:
          repository: org/security-workflows
          path: central

      - name: Token de GitHub App
        id: app
        uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ secrets.REPORT_APP_ID }}
          private-key: ${{ secrets.REPORT_APP_KEY }}
          owner: ${{ github.repository_owner }}

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install requests jinja2 weasyprint

      - name: Generar PDF
        env:
          GH_TOKEN: ${{ steps.app.outputs.token }}
          ORG: ${{ github.repository_owner }}
          TARGET_REPO: ${{ inputs.repository }}
        run: python central/scripts/security_report.py --out security-report.pdf

      - name: Publicar como artifact
        uses: actions/upload-artifact@v4
        with:
          name: security-report-${{ github.run_id }}
          path: security-report.pdf
          retention-days: 90
```

Así lo llama un repositorio de aplicación:

```yaml
jobs:
  security-report:
    uses: org/security-workflows/.github/workflows/security-report.yml@v1
    with:
      repository: ${{ github.repository }}
    secrets: inherit
```

### 2.6 Esqueleto del script (`scripts/security_report.py`)

```python
import os, datetime, argparse, requests
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

API = "https://api.github.com"
S = requests.Session()
S.headers.update({
    "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
})

def paged(url, **params):
    params.setdefault("per_page", 100)
    while url:
        r = S.get(url, params=params); r.raise_for_status()
        yield from r.json()
        url, params = r.links.get("next", {}).get("url"), None

def scope():
    repo = os.environ.get("TARGET_REPO")
    return f"{API}/repos/{repo}" if repo else f"{API}/orgs/{os.environ['ORG']}"

def main(out):
    base = scope()
    data = {
        "code":    list(paged(f"{base}/code-scanning/alerts", state="open")),
        "deps":    list(paged(f"{base}/dependabot/alerts", state="open")),
        "secrets": list(paged(f"{base}/secret-scanning/alerts", state="open")),
        "generated": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "target": os.environ.get("TARGET_REPO") or os.environ["ORG"],
    }
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "..", "templates")))
    html = env.get_template("report.html.j2").render(**data)
    HTML(string=html).write_pdf(out)

if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("--out", required=True)
    main(p.parse_args().out)
```

La plantilla `templates/report.html.j2` debería incluir:

- Portada con la organización o el repositorio, la fecha y el commit.
- Resumen ejecutivo: totales por herramienta y por severidad, y la comparación con el reporte anterior.
- Tablas detalladas: regla o advisory, severidad, repositorio, ubicación, antigüedad y enlace a la alerta.
- La sección de **excepciones vigentes y vencidas** (ver sección 3).

### 2.7 Opciones de publicación

| Destino | Cómo | Cuándo conviene |
|---|---|---|
| Artifact del run | `actions/upload-artifact` | Siempre, porque deja trazabilidad del run |
| GitHub Release | `gh release upload <tag> security-report.pdf` | Para adjuntar el reporte de seguridad a cada versión |
| Rama `reports` / GitHub Pages | Commit del PDF desde el workflow | Para tener un histórico navegable |
| Teams / Slack | Webhook con un resumen y el enlace al PDF | Para avisar a los equipos |
| Email | Acción SMTP o Microsoft Graph API | Para enviárselo a gerencia o auditoría |
| Azure Blob / S3 / SharePoint | CLI del proveedor con OIDC (`azure/login`, `aws-actions/configure-aws-credentials`) | Para retención a largo plazo y auditorías |

### 2.8 Alternativas

- **Pandoc + LaTeX** (Markdown → PDF): sirve si el reporte ya existe como Markdown, por ejemplo el `GITHUB_STEP_SUMMARY` que ya genera este repo.
- **Chromium headless / Playwright** (`page.pdf()`): da la mayor fidelidad de CSS, pero pesa más.
- **Conversores SARIF → HTML/PDF** de la comunidad: sirven para reportes de un solo repositorio, pero no consolidan Dependabot ni secret scanning.
- **Power BI / Grafana** alimentados por la API: son una buena opción si lo que se busca es un dashboard en vivo y no un documento.

---

## 3. Excepción, exclusión y control mínimo de vulnerabilidades de dependencias

### 3.1 Objetivo

Lo que se busca es:

- Bloquear las dependencias vulnerables **por encima de un umbral mínimo**, tanto de paquetes como de **acciones de GitHub Actions**.
- Permitir **excepciones justificadas**, con responsable, aprobación y **fecha de vencimiento**.
- Que los equipos **no puedan desactivar el control** desde su propio repositorio.
- Dejar todo **auditado y reportado**.

### 3.2 Piezas que ofrece GitHub

| Pieza | Para qué sirve | Limitación |
|---|---|---|
| `actions/dependency-review-action` | Gate en PR/push: `fail-on-severity`, `fail-on-scopes`, `allow-ghsas`, `deny-packages`, `deny-groups`, `allow-licenses`/`deny-licenses`, `allow-dependencies-licenses`, `warn-only`, `comment-summary-in-pr`, OpenSSF Scorecard | Solo evalúa **cambios** (diff), no el inventario completo |
| `config-file` externo | La configuración puede vivir en un **repositorio central**: `config-file: org/security-policies/dependency-review.yml@main` (con `external-repo-token` si el repositorio es privado) | Las excepciones aplican a todos los repositorios que usan ese archivo, salvo que se segmenten |
| **Dependabot auto-triage rules** | Reglas a nivel repositorio u organización que **descartan o posponen alertas automáticamente** según severidad, paquete, ecosistema, scope (dev/runtime), manifiesto, GHSA/CVE, CWE o EPSS | Las reglas personalizadas en repositorios privados requieren Code Security |
| API para descartar alertas | `PATCH /repos/{o}/{r}/dependabot/alerts/{n}` con `state=dismissed`, `dismissed_reason` (`tolerable_risk`, `not_used`, `inaccurate`, `fix_started`, `no_bandwidth`) y `dismissed_comment` | El descarte manual no vence solo; hay que reabrirlo por proceso |
| `ignore` en `dependabot.yml` | Evita que Dependabot abra **PRs de actualización** para ciertas dependencias o versiones | **No suprime alertas** ni afecta a dependency review |
| Rulesets *Require workflows* | Obliga a ejecutar el workflow central de dependency review en los repositorios elegidos | Requiere un plan Team o Enterprise |
| Políticas de Actions | *Allow select actions* y exigencia de **fijar por SHA** a nivel organización | Controla qué acciones se usan, no sus CVEs |

### 3.3 Diseño recomendado

```text
org/security-policies (repo central, protegido con CODEOWNERS = equipo de seguridad)
├── dependency-review.yml        # política base (umbral mínimo)
├── exceptions.yml               # registro de excepciones con vencimiento
└── .github/workflows/
    └── dependency-gate.yml      # workflow reutilizable / requerido por ruleset
```

**a) Política base (control mínimo)**: `dependency-review.yml`

```yaml
fail-on-severity: high            # mínimo: bloquear high y critical
fail-on-scopes: [runtime]         # las dependencias de desarrollo solo advierten
comment-summary-in-pr: on-failure
vulnerability-check: true
license-check: true
deny-licenses: [AGPL-3.0, GPL-3.0]
show-openssf-scorecard: true
warn-on-openssf-scorecard-level: 3
allow-ghsas: []                   # se completa dinámicamente desde exceptions.yml
```

**b) Registro de excepciones**: `exceptions.yml`

```yaml
exceptions:
  - id: EXC-2026-001
    ghsa: GHSA-q2q7-5pp4-w6pg          # urllib3 1.26.4 (CVE-2021-33503)
    package: urllib3
    ecosystem: pip
    repositories: [org/BIT-DEVOPS-DEMO-SCAN-AVANCED-SECURITY]   # alcance acotado; "*" = toda la org
    reason: tolerable_risk
    justification: "Repo demo, no se despliega. Vulnerabilidad requerida para la demo."
    requested_by: "@equipo-devops"
    approved_by: "@equipo-seguridad"
    expires: 2026-12-31
```

Reglas del proceso:

- Toda excepción entra por **PR** al repositorio central y requiere la aprobación de `CODEOWNERS` (el equipo de seguridad).
- Los campos obligatorios son `ghsa`, `repositories`, `justification`, `approved_by` y `expires`, con un máximo de 90 días, por ejemplo.
- Una excepción **vencida deja de aplicarse sola** y el gate vuelve a fallar.
- Las excepciones `critical` solo pueden tener un vencimiento corto o directamente no se permiten.

**c) Workflow central (gate)**: `dependency-gate.yml`

```yaml
name: Dependency Gate
on:
  workflow_call:

permissions:
  contents: read
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Traer políticas centrales
        uses: actions/checkout@v4
        with:
          repository: org/security-policies
          path: .policies
          token: ${{ secrets.POLICIES_READ_TOKEN }}

      - name: Resolver excepciones vigentes para este repo
        id: exc
        run: |
          pip install pyyaml >/dev/null
          python - <<'PY' >> "$GITHUB_OUTPUT"
          import yaml, datetime, os
          repo = os.environ["GITHUB_REPOSITORY"]
          today = datetime.date.today()
          data = yaml.safe_load(open(".policies/exceptions.yml"))["exceptions"]
          active = [e["ghsa"] for e in data
                    if (repo in e["repositories"] or "*" in e["repositories"])
                    and e["expires"] >= today]
          print("allow-ghsas=" + ",".join(active))
          PY

      - uses: actions/dependency-review-action@v4
        with:
          config-file: .policies/dependency-review.yml
          allow-ghsas: ${{ steps.exc.outputs.allow-ghsas }}
          # en push (sin PR) usar los SHAs del evento:
          base-ref: ${{ github.event.pull_request.base.sha || github.event.before }}
          head-ref: ${{ github.event.pull_request.head.sha || github.sha }}
```

**d) Cómo se hace obligatorio**

- Ruleset de organización → *Require workflows to pass before merging* → `org/security-policies/.github/workflows/dependency-gate.yml@main`, aplicado a todos los repositorios (o a los que tengan una propiedad personalizada como `tier=prod`).
- Política de Actions de la organización: *Allow GitHub-created and verified actions + lista blanca* y **exigir fijación por SHA**.
- Dependabot habilitado para el ecosistema `github-actions` en todos los repositorios, mediante una security configuration. Así se cubren acciones vulnerables como `actions/download-artifact@v4.1.2` (CVE-2024-42471), que es la que usa este demo.

**e) Mantener las alertas alineadas con las excepciones**

El gate de PR (dependency review) y las **alertas de Dependabot** son mecanismos distintos. Para que no queden alertas abiertas que ya tienen una excepción aprobada:

- Un workflow programado en el repositorio central recorre `exceptions.yml` y, por API, **descarta** las alertas que coinciden (`dismissed_reason=tolerable_risk` y un `dismissed_comment` con el ID de la excepción).
- Cuando la excepción vence, el mismo workflow **reabre** la alerta (`state=open`).
- Para los casos genéricos, por ejemplo *"descartar las low de dependencias de desarrollo"*, se pueden usar las **Dependabot auto-triage rules** de la organización en lugar de scripts.

### 3.4 Resumen de lo que se necesita

| Necesidad | Elemento |
|---|---|
| Umbral mínimo | `fail-on-severity` + `fail-on-scopes` en una configuración central |
| Excepción puntual | `allow-ghsas`, generado desde `exceptions.yml` con vencimiento |
| Exclusión de paquetes o licencias | `deny-packages`, `allow-dependencies-licenses` y `deny-licenses` |
| Gobierno y aprobación | Repositorio central + CODEOWNERS + protección de rama |
| Que no se pueda evitar | Ruleset *Require workflows* + políticas de Actions |
| Alertas consistentes | Auto-triage rules + API para descartar y reabrir |
| Evidencia y auditoría | Historial de git de `exceptions.yml` + sección de excepciones en el PDF (sección 2) |
| Credenciales | GitHub App o token de solo lectura para el repositorio de políticas; GitHub App con `Dependabot alerts: write` para descartar y reabrir |
| Licencias | Code Security en repositorios privados (dependency review y reglas personalizadas) |

---

## 4. Copilot Autofix

### 4.1 Qué es

**Copilot Autofix** es la función de GitHub Code Security que usa IA generativa para **proponer correcciones de código** a las alertas de code scanning. Junto con cada propuesta entrega una **explicación en lenguaje natural** de la vulnerabilidad y del cambio sugerido.

- **No requiere una licencia de GitHub Copilot.** Viene incluido con **GitHub Code Security** en los repositorios privados y es **gratuito en los públicos**.
- Está **habilitado por defecto** en los repositorios que tienen code scanning con CodeQL.

### 4.2 Funcionamiento

```text
CodeQL detecta alerta ──► Autofix arma el prompt con:
                            • descripción y ayuda de la query CodeQL
                            • ubicación y flujo de datos (source → sink)
                            • fragmentos de código relevantes (puede abarcar varios archivos)
                          ──► LLM genera parche + explicación
                          ──► GitHub valida el parche (sintaxis, que aplique sobre el código)
                          ──► Se muestra como sugerencia en el PR o en la alerta
```

- El parche puede tocar **varios lugares de un archivo**, y a veces más de un archivo. También puede proponer **agregar una dependencia**, por ejemplo una librería de sanitización.
- El resultado **no es determinístico**: ejecutarlo dos veces sobre la misma alerta puede dar propuestas distintas, o ninguna.
- GitHub declara que el código que se envía **no se usa para entrenar modelos** ni se retiene más allá de lo necesario para generar la sugerencia.

### 4.3 Cómo se usa

| Escenario | Flujo |
|---|---|
| **En Pull Requests** | Cuando CodeQL encuentra una alerta nueva en un PR, Autofix publica un comentario con la explicación y una **sugerencia de código**. El desarrollador puede *Commit suggestion*, editarla o descartarla |
| **Alertas existentes en la rama por defecto** | En *Security → Code scanning → alerta → **Generate fix***. Se revisa la propuesta y se elige **Create PR with fix** (o se abre en un Codespace para ajustarla) |
| **Security campaigns** | Se crea una campaña sobre un conjunto de alertas de la organización y Autofix genera correcciones en lote, que se pueden asignar a los responsables o al **agente de código de Copilot** para que abra los PRs |
| **Herramientas de terceros** | Hay soporte (en algunos casos en preview) para alertas de herramientas externas como ESLint. Se habilita aparte |

Configuración:

- **Organización / enterprise**: *Settings → Code security → Global settings → Copilot Autofix*, donde se puede activar o desactivar, también para herramientas de terceros.
- **Repositorio**: *Settings → Code security → Code scanning → Copilot Autofix*.

### 4.4 Alcance

| Aspecto | Alcance |
|---|---|
| Fuente de alertas | Principalmente **CodeQL**; terceros de forma limitada |
| Lenguajes | C#, C/C++, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift, además de **GitHub Actions** (workflows) y otros que se van agregando según el soporte de CodeQL |
| Tipos de vulnerabilidad | La mayoría de las queries de seguridad (`security-extended`): inyecciones (SQL, comandos, código), XSS, path traversal, deserialización insegura, SSRF, criptografía débil, configuraciones inseguras, etc. |
| Qué **no** hace | No corrige **dependencias vulnerables** (de eso se encarga Dependabot security updates), no corrige **secretos expuestos** (hay que rotarlos), no garantiza que el parche compile ni que pase los tests, y no cubre todas las queries |
| Limitaciones | Puede no generar una propuesta, puede proponer correcciones parciales o cambios de comportamiento, y depende del contexto que se le envía (código muy distribuido o lenguajes con poco soporte bajan la calidad) |
| Responsabilidad | La propuesta **siempre debe revisarla un humano** y validarla con los tests y con un nuevo escaneo de CodeQL antes del merge |

### 4.5 Casos de uso

**Generales**

1. **Shift-left en PRs**: el desarrollador recibe la corrección en el mismo PR donde introdujo la vulnerabilidad, lo que reduce el tiempo de remediación (MTTR).
2. **Reducir la deuda de seguridad**: generar correcciones para el backlog de alertas antiguas de la rama por defecto.
3. **Remediación masiva con security campaigns**: por ejemplo, *"eliminar todos los `sql-injection` de la organización antes del Qn"*.
4. **Capacitación**: la explicación que acompaña cada fix sirve como material de aprendizaje de codificación segura.
5. **Endurecer workflows de Actions**: corregir inyecciones de expresiones `${{ }}` en pasos `run`.

**Aplicados a las alertas esperadas en este repositorio**

| Alerta | Archivo | Corrección típica que propone Autofix |
|---|---|---|
| `py/sql-injection` | `app/app.py` (`/users`) | Pasar de concatenar strings a **consultas parametrizadas** (`cursor.execute("... WHERE name = ?", (name,))`) |
| `py/command-line-injection` | `app/app.py` (`/ping`) | Usar `subprocess.run([...], shell=False)` con la lista de argumentos y validar el host |
| `py/reflective-xss` | `app/app.py` (`/hello`) | Escapar la salida con `markupsafe.escape()` o usar plantillas con auto-escape |
| `py/path-injection` | `app/app.py` (`/files`) | Usar `werkzeug.utils.safe_join` o normalizar la ruta y validar que quede dentro del directorio base |
| `py/flask-debug` | `app/app.py` | Quitar `debug=True` o controlarlo con una variable de entorno |
| `actions/code-injection` | `.github/workflows/advanced-security.yml` (paso *Mostrar commit*) | Mover `github.event.head_commit.message` a `env:` y referenciarlo como `"$COMMIT_MSG"` en el script |

### 4.6 Buenas prácticas

- Tratar Autofix como un **asistente**, no como una corrección automática: exigir revisión con CODEOWNERS y que los tests pasen.
- Combinarlo con el ruleset *Require code scanning results*, para que el PR no se pueda mergear hasta que la alerta desaparezca.
- Medir el impacto en Security overview (alertas corregidas con Autofix, tiempo de remediación).
- Hacer seguimiento de los fixes que se descartan, porque suelen indicar falsos positivos o queries que conviene ajustar.

---

## 5. Referencias

- About GitHub Advanced Security: <https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security>
- Code scanning: <https://docs.github.com/en/code-security/code-scanning>
- Copilot Autofix for code scanning: <https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/responsible-use-autofix-code-scanning>
- Security campaigns: <https://docs.github.com/en/code-security/securing-your-organization/fixing-security-alerts-at-scale>
- Dependency review action: <https://github.com/actions/dependency-review-action>
- Configuring dependency review: <https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/configuring-the-dependency-review-action>
- Dependabot auto-triage rules: <https://docs.github.com/en/code-security/dependabot/dependabot-auto-triage-rules>
- REST API, Dependabot alerts: <https://docs.github.com/en/rest/dependabot/alerts>
- REST API, Code scanning: <https://docs.github.com/en/rest/code-scanning/code-scanning>
- REST API, Secret scanning: <https://docs.github.com/en/rest/secret-scanning/secret-scanning>
- Reusable workflows: <https://docs.github.com/en/actions/sharing-automations/reusing-workflows>
- Rulesets, required workflows y code scanning: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>
- WeasyPrint: <https://doc.courtbouillon.org/weasyprint/>
