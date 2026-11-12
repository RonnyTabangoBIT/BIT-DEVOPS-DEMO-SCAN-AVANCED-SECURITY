# Investigación: GitHub Advanced Security

Este documento reúne lo investigado sobre:

1. El uso de **GitHub Advanced Security (GHAS)**.
2. Cómo **generar y publicar reportes en PDF** desde un **workflow centralizado**.
3. Qué hace falta para tener un mecanismo de **excepción, exclusión o control mínimo** de vulnerabilidades de dependencias en GitHub Actions, y cómo funciona el **flujo del control de excepciones**.
4. **Copilot Autofix**: cómo funciona, cómo se usa, qué alcance tiene, en qué casos sirve y cómo se remedia en lote con **security campaigns y el agente de Copilot**, con la lista de requisitos para implementarlo.
5. **Excepciones de code scanning**: archivo de excepciones y gate, con el mismo esquema que las dependencias; y qué queda para el producto final (descartes en la interfaz, secret scanning, delegated dismissal y bypass).
6. **Gobierno del merge**: rulesets, CODEOWNERS (grupos de aprobadores) y aprobación automática para la demo.

> Las funcionalidades, licencias y precios de GitHub cambian seguido. Antes de tomar decisiones de compra o arquitectura, conviene revisar las [referencias](#7-referencias) oficiales.

---

## Índice

- [1. GitHub Advanced Security](#1-github-advanced-security)
- [2. Reportes PDF desde un workflow centralizado](#2-reportes-pdf-desde-un-workflow-centralizado)
- [3. Excepción, exclusión y control mínimo de vulnerabilidades de dependencias](#3-excepción-exclusión-y-control-mínimo-de-vulnerabilidades-de-dependencias)
- [4. Copilot Autofix](#4-copilot-autofix)
- [5. Excepciones de code scanning](#5-excepciones-de-code-scanning)
- [6. Gobierno del merge: rulesets, CODEOWNERS y aprobaciones](#6-gobierno-del-merge-rulesets-codeowners-y-aprobaciones)
- [7. Referencias](#7-referencias)

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
- Los productos se compran para **organizaciones**. En repositorios **privados de cuentas personales** no se pueden habilitar code scanning ni dependency review; en repositorios **públicos** personales sí funcionan sin costo (es el caso de esta demo).
- Se cobra por **committer activo único**, es decir, cada usuario que hizo push en los últimos 90 días a un repositorio que tiene la función habilitada.

### 1.2 Componentes principales

| Componente | Qué hace | Dónde se ve |
|---|---|---|
| **Dependency graph** | Arma el inventario de dependencias a partir de los manifiestos (`requirements.txt`, `Pipfile`, `package.json`, workflows de Actions, etc.) y puede exportar un SBOM en formato SPDX | Insights → Dependency graph |
| **Dependabot alerts** | Avisa cuando una dependencia está afectada por un advisory de la GitHub Advisory Database. Solo se generan para la **rama predeterminada** | Security → Dependabot |
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
- **Advanced setup**: un workflow propio con `github/codeql-action`, como el [workflow de este repo](.github/workflows/advanced-security.yml). Permite elegir query suites (`security-extended`, `security-and-quality`), una matriz de lenguajes, modos de build y categorías de SARIF. **Default y advanced setup no pueden estar activos a la vez**: si el default setup está habilitado, el workflow falla al subir resultados.
- **Herramientas de terceros**: cualquier herramienta que genere SARIF (Trivy, Semgrep, Checkmarx, etc.) se puede subir con `github/codeql-action/upload-sarif`.

### 1.4 Cómo hacer obligatorios los controles a nivel organización

| Mecanismo | Uso |
|---|---|
| **Security configurations** | Habilitan dependency graph, Dependabot, code scanning y secret scanning en todos los repositorios o en un subconjunto |
| **Rulesets: "Require status checks to pass"** | Bloquea el merge hasta que los jobs indicados (por ejemplo `Dependency Review` o `Dependabot severidad mínima`) terminen en *success* |
| **Rulesets: "Require code scanning results"** | Bloquea el merge si el PR introduce alertas de code scanning por encima de un umbral (por ejemplo, `High or higher`) |
| **Rulesets: "Require workflows to pass before merging"** | Obliga a ejecutar un workflow que vive en un **repositorio central** (por ejemplo, el de dependency review) en todos los repositorios elegidos, sin que cada equipo tenga que copiarlo. Es una regla de **ruleset de organización** |
| **Rulesets: "Require a pull request" + CODEOWNERS** | Exige aprobaciones y, opcionalmente, la aprobación de los dueños de cada ruta (ver [sección 6](#6-gobierno-del-merge-rulesets-codeowners-y-aprobaciones)) |
| **Políticas de Actions** | Lista de acciones permitidas y exigencia de fijar acciones por SHA, a nivel organización o enterprise |
| **Delegated bypass / delegated alert dismissal** | Exige que un revisor apruebe antes de saltarse push protection o descartar alertas (ver [5.6](#56-fuera-de-la-versión-mínima-para-el-producto-final)) |

### 1.5 Relación con este repositorio demo

| Función | Estado en este repo |
|---|---|
| CodeQL (Python + Actions) | ✅ Job `codeql`, advanced setup con `security-extended` |
| Dependency review | ✅ Job `dependency-review` con `fail-on-severity: moderate` (dependencias corregidas: `urllib3==2.8.0`, `download-artifact@v4.3.0`) |
| Dependabot | ✅ `.github/dependabot.yml` (pip + github-actions) |
| Control mínimo por severidad | ✅ Job `dependabot-severity-gate` con umbrales `MAX_CRITICAL`, `MAX_HIGH`, `MAX_MEDIUM`, `MAX_LOW` (ver [3.5](#35-implementación-en-este-repositorio-umbral-excepciones-y-reglas-por-versión)) |
| Control de excepciones y reglas por versión | ✅ `.github/security/excepciones.yml`: excepciones por GHSA, paquete, versión y severidad con vencimiento, y umbrales por paquete/versión (ver [3.5](#35-implementación-en-este-repositorio-umbral-excepciones-y-reglas-por-versión)) |
| CODEOWNERS | ✅ `.github/CODEOWNERS`: aprobador por ruta; protege excepciones, workflow y umbrales (ver [6.4](#64-archivo-codeowners)) |
| Copilot Autofix | ✅ `demo/copilot-autofix/` (errores adicionales en un PR dedicado) |
| Autofix con agente (remediación en lote) | ✅ Workflow **Autofix Agent**: requisitos, autofix por API y PR de remediación (ver [4.9](#49-prueba-en-este-repositorio-workflow-autofix-agent)) |
| Gate de code scanning con excepciones | ✅ Job `Code scanning severidad mínima` con `.github/security/excepciones-codigo.yml`: mismo esquema que el de dependencias (ver [5.1](#51-cómo-funciona)) |
| Ejecución con push a `main` | ✅ Los workflows corren con cada push a `main` (ver [5.5](#55-ejecución-con-push-a-main)) |
| Descartes en la interfaz, secret scanning, delegated dismissal y bypass, security campaigns | ⚙️ Documentado; requiere organización (ver [4.7](#47-autofix-con-agente-security-campaigns-y-agente-de-código-de-copilot) y [5.6](#56-fuera-de-la-versión-mínima-para-el-producto-final)) |
| Ruleset sobre `main` + aprobación | ✅ Status checks obligatorios + aprobación automática para la demo (ver [sección 6](#6-gobierno-del-merge-rulesets-codeowners-y-aprobaciones)) |
| Secret scanning / Push protection | ⚙️ Se habilita en Settings, no requiere workflow |
| Reportes PDF centralizados | ❌ Pendiente (ver sección 2) |
| Repositorio central de excepciones (varios repos) | ❌ Pendiente; diseño en [3.3](#33-diseño-recomendado) y flujo en [3.4](#34-flujo-del-control-de-excepciones) |
| Sincronización de alertas de Dependabot con excepciones | ❌ Pendiente (paso 6 de [3.4](#34-flujo-del-control-de-excepciones)) |

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

Un **repositorio central** (por ejemplo, `org/security-workflows`) contiene el workflow `.github/workflows/security-report.yml`, que se dispara por `schedule`, `workflow_dispatch` o `workflow_call`. El workflow ejecuta estos pasos:

1. Obtiene un **token de GitHub App** con permisos de solo lectura sobre las alertas.
2. Ejecuta un **script** que consulta las APIs de code scanning, Dependabot y secret scanning.
3. Renderiza una **plantilla HTML** (Jinja2) con el CSS corporativo.
4. Convierte el HTML a **PDF** con WeasyPrint.
5. **Publica** el PDF: artifact, release, Teams/Slack/email o almacenamiento (Blob, S3, SharePoint).

Hay dos modalidades:

1. **Reporte consolidado de la organización**: corre por `schedule` (por ejemplo, semanal o mensual) en el repositorio central y consulta los endpoints de la organización (`/orgs/{org}/...`). Ningún repositorio de aplicación tiene que hacer nada.
2. **Reporte por repositorio**: cada repositorio llama al workflow reutilizable con `workflow_call`, por ejemplo al final del pipeline de `main` o en cada release. Si se quiere que sea obligatorio, se exige con un ruleset de tipo *Require workflows*.

### 2.3 Requisitos

| Requisito | Detalle |
|---|---|
| Repositorio central | Por ejemplo, `org/security-workflows`. En *Settings → Actions → General → Access* hay que permitir el acceso desde los repositorios de la organización |
| **GitHub App** (recomendado) | Permisos de **lectura**: `Code scanning alerts`, `Dependabot alerts`, `Secret scanning alerts`, `Contents` y `Metadata`, y `Administration: read` si se necesita listar repositorios. Instalada en la organización. El `client-id` de la App y la `private-key` se guardan como secretos de la organización |
| Por qué no usar `GITHUB_TOKEN` | Solo tiene acceso al repositorio donde corre el workflow, **no puede leer las alertas de la organización** y **no tiene permiso para leer alertas de Dependabot** |
| Licencia | Code Security y Secret Protection en los repositorios privados que se quieran incluir |
| Runner | `ubuntu-latest` alcanza: WeasyPrint se instala con pip. Si faltan las librerías de Pango, se instalan con `sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0` |

### 2.4 Endpoints de la API que se usan

| Dato | Organización | Repositorio |
|---|---|---|
| Code scanning | `GET /orgs/{org}/code-scanning/alerts` | `GET /repos/{owner}/{repo}/code-scanning/alerts` |
| Dependabot | `GET /orgs/{org}/dependabot/alerts` | `GET /repos/{owner}/{repo}/dependabot/alerts` |
| Secret scanning | `GET /orgs/{org}/secret-scanning/alerts` | `GET /repos/{owner}/{repo}/secret-scanning/alerts` |
| SBOM | — | `GET /repos/{owner}/{repo}/dependency-graph/sbom` |

Todos aceptan filtros como `state=open` y `per_page=100`, y devuelven resultados paginados mediante el header `Link`. Code scanning filtra con `severity` (por ejemplo `critical`, `high`) y Dependabot con `severity=critical,high`.

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
      REPORT_APP_CLIENT_ID:
        required: true
      REPORT_APP_KEY:
        required: true

permissions:
  contents: read

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      # El token va primero: se usa también para leer el repo central si es privado.
      - name: Token de GitHub App
        id: app
        uses: actions/create-github-app-token@v3
        with:
          client-id: ${{ secrets.REPORT_APP_CLIENT_ID }}   # en v3 reemplaza a app-id (deprecado)
          private-key: ${{ secrets.REPORT_APP_KEY }}
          owner: ${{ github.repository_owner }}

      - name: Checkout del repo central (script + plantilla)
        uses: actions/checkout@v4
        with:
          repository: org/security-workflows
          path: central
          token: ${{ steps.app.outputs.token }}

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
        "generated": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "target": os.environ.get("TARGET_REPO") or os.environ["ORG"],
    }
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "..", "templates")),
                      autoescape=True)
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

> `autoescape=True` es importante: los títulos y descripciones de las alertas vienen de fuentes externas y no deben interpretarse como HTML.

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
| `actions/dependency-review-action` | Gate en PR/push: `fail-on-severity`, `fail-on-scopes`, `allow-ghsas`, `deny-packages`, `deny-groups`, `allow-licenses`/`deny-licenses`, `allow-dependencies-licenses`, `warn-only`, `comment-summary-in-pr`, OpenSSF Scorecard | Solo evalúa **cambios** (diff): una dependencia vulnerable que ya estaba en la rama base y no se modifica **no se reporta** |
| `config-file` externo | La configuración puede vivir en un **repositorio central**: `config-file: org/security-policies/dependency-review.yml@main` (con `external-repo-token` si el repositorio es privado) | Las excepciones aplican a todos los repositorios que usan ese archivo, salvo que se segmenten |
| **Dependabot auto-triage rules** | Reglas a nivel repositorio u organización que **descartan o posponen alertas automáticamente** según severidad, paquete, ecosistema, scope (dev/runtime), manifiesto, GHSA/CVE, CWE o EPSS | Las reglas personalizadas en repositorios privados requieren Code Security |
| API para descartar alertas | `PATCH /repos/{o}/{r}/dependabot/alerts/{n}` con `state=dismissed`, `dismissed_reason` (`tolerable_risk`, `not_used`, `inaccurate`, `fix_started`, `no_bandwidth`) y `dismissed_comment` | El descarte manual no vence solo; hay que reabrirlo por proceso |
| `ignore` en `dependabot.yml` | Evita que Dependabot abra **PRs de actualización** para ciertas dependencias o versiones | **No suprime alertas** ni afecta a dependency review |
| API de la GitHub Advisory Database | `GET /advisories?ecosystem=pip&affects=<paquete>` permite evaluar el **inventario completo** de un manifiesto en cualquier rama, con `GITHUB_TOKEN` | Hay que evaluar los rangos de versión localmente; es la base del gate de este repo (ver [3.5](#35-implementación-en-este-repositorio-umbral-excepciones-y-reglas-por-versión)) |
| Rulesets *Require workflows* | Obliga a ejecutar el workflow central de dependency review en los repositorios elegidos | Es una regla de **ruleset de organización**; no existe para repositorios de cuentas personales |
| Políticas de Actions | *Allow select actions* y exigencia de **fijar por SHA** a nivel organización | Controla qué acciones se usan, no sus CVEs |

### 3.3 Diseño recomendado

El repositorio central de políticas (por ejemplo, `org/security-policies`) está protegido con CODEOWNERS (equipo de seguridad) y contiene:

| Archivo | Contenido |
|---|---|
| `dependency-review.yml` | Política base (umbral mínimo) |
| `exceptions.yml` | Registro de excepciones con vencimiento |
| `.github/workflows/dependency-gate.yml` | Workflow reutilizable, requerido por ruleset |

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
    ghsa: GHSA-462w-v97r-4m45          # jinja2 2.10 (CVE-2019-10906), high
    package: jinja2
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

> Los repositorios que llaman a este workflow reutilizable deben otorgar `pull-requests: write` en su propio bloque `permissions`, porque un workflow llamado no puede tener más permisos que el que lo llama.

**d) Cómo se hace obligatorio**

- Ruleset de organización → *Require workflows to pass before merging* → `org/security-policies/.github/workflows/dependency-gate.yml@main`, aplicado a todos los repositorios (o a los que tengan una propiedad personalizada como `tier=prod`).
- Política de Actions de la organización: *Allow GitHub-created and verified actions + lista blanca* y **exigir fijación por SHA**.
- Dependabot habilitado para el ecosistema `github-actions` en todos los repositorios, mediante una security configuration. Así se cubren acciones vulnerables como `actions/download-artifact@v4.1.2` (CVE-2024-42471), que este demo usaba y que se corrigió a `v4.3.0`.

**e) Mantener las alertas alineadas con las excepciones**

El gate de PR (dependency review) y las **alertas de Dependabot** son mecanismos distintos. Para que no queden alertas abiertas que ya tienen una excepción aprobada:

- Un workflow programado en el repositorio central recorre `exceptions.yml` y, por API, **descarta** las alertas que coinciden (`dismissed_reason=tolerable_risk` y un `dismissed_comment` con el ID de la excepción).
- Cuando la excepción vence, el mismo workflow **reabre** la alerta (`state=open`).
- Para los casos genéricos, por ejemplo *"descartar las low de dependencias de desarrollo"*, se pueden usar las **Dependabot auto-triage rules** de la organización en lugar de scripts.

### 3.4 Flujo del control de excepciones

El control de excepciones tiene un **ciclo de vida**: una vulnerabilidad bloquea, alguien pide una excepción, seguridad la aprueba o la rechaza, la excepción se aplica de forma automática mientras está vigente y deja de aplicarse cuando vence.

Este flujo describe el diseño para una organización, con un repositorio central de políticas. La versión implementada en este repo, con el archivo de excepciones dentro del mismo repositorio, está en [3.5.6](#356-cómo-se-aplica-el-flujo-de-34-en-este-repo).

**Paso 1 – El gate detecta y bloquea.** Un PR agrega o actualiza una dependencia con una vulnerabilidad `high` o `critical`. El workflow `dependency-gate` falla, el PR no se puede mergear (por el ruleset) y el comentario de dependency review indica el paquete, la severidad y el GHSA.

**Paso 2 – El equipo evalúa antes de pedir una excepción.** Lo primero siempre es **actualizar** la dependencia a una versión corregida (o aplicar el PR de Dependabot). Solo si no hay versión corregida, si la actualización rompe compatibilidad o si el código vulnerable no se usa, se justifica una excepción.

**Paso 3 – Solicitud por PR al repositorio central.** El equipo abre un PR en `org/security-policies` que agrega una entrada en `exceptions.yml` con: `ghsa`, `package`, `repositories` (alcance mínimo), `reason`, `justification`, `requested_by` y `expires`. Un workflow de validación del repositorio central revisa que estén todos los campos, que `expires` no supere el máximo permitido y que no se pida una excepción `critical` fuera de política.

**Paso 4 – Aprobación del equipo de seguridad.** CODEOWNERS asigna automáticamente al equipo de seguridad como revisor. El ruleset del repositorio central exige su aprobación (*Require review from Code Owners*), así que **nadie del equipo solicitante puede aprobarse a sí mismo**. Seguridad completa `approved_by` y aprueba, o pide cambios (alcance más chico, vencimiento más corto) o rechaza.

**Paso 5 – Merge y aplicación automática.** Al mergear, la excepción queda vigente. No hay que tocar el repositorio de la aplicación: en el siguiente run del gate, el paso *Resolver excepciones vigentes* lee `exceptions.yml`, filtra las excepciones del repositorio con `expires >= hoy` y las pasa como `allow-ghsas` a dependency review. El PR original vuelve a ejecutar los checks y pasa.

**Paso 6 – Sincronización de alertas.** El workflow programado del repositorio central descarta en Dependabot las alertas cubiertas por excepciones vigentes (`tolerable_risk` + ID de la excepción en el comentario), para que Security overview no muestre como pendiente algo que ya se aceptó formalmente.

**Paso 7 – Vencimiento.** Cuando llega la fecha `expires`, la excepción **deja de aplicarse sola**: el siguiente run del gate ya no la incluye en `allow-ghsas`, el gate vuelve a fallar en cualquier PR que toque esa dependencia y el workflow programado **reabre** la alerta. Para seguir, el equipo tiene que corregir la dependencia o pedir una **renovación** (un nuevo PR con nueva justificación). Conviene avisar antes del vencimiento (por ejemplo, 15 días antes) con un issue o un mensaje a Teams/Slack.

**Paso 8 – Auditoría y reporte.** El historial de git de `exceptions.yml` registra quién pidió, quién aprobó, cuándo y por qué. El reporte PDF (sección 2) incluye las excepciones **vigentes, por vencer y vencidas**.

Comportamiento del gate según el caso:

| Caso | Resultado del gate |
|---|---|
| Vulnerabilidad bajo el umbral (`fail-on-severity`) | ✅ Pasa (solo advertencia) |
| Vulnerabilidad sobre el umbral, sin excepción | ❌ Falla, el merge queda bloqueado |
| Vulnerabilidad sobre el umbral, con excepción vigente para ese repositorio | ✅ Pasa |
| Excepción vigente, pero para **otro** repositorio | ❌ Falla (el alcance no aplica) |
| Excepción vencida | ❌ Falla y la alerta se reabre |
| Excepción mergeada sin aprobación de seguridad | No puede ocurrir: el ruleset del repositorio central lo impide |

Responsables:

| Rol | Responsabilidad |
|---|---|
| Equipo de desarrollo | Corregir primero; si no se puede, pedir la excepción con justificación y plan de corrección |
| Equipo de seguridad (CODEOWNERS) | Aprobar o rechazar, definir alcance y vencimiento, revisar renovaciones |
| Plataforma / DevOps | Mantener el workflow central, los rulesets y la sincronización de alertas |
| Auditoría | Revisar el historial de `exceptions.yml` y el reporte PDF |

### 3.5 Implementación en este repositorio: umbral, excepciones y reglas por versión

Este repo implementa el **control mínimo** y el **control de excepciones** con el job `dependabot-severity-gate` ([`severity_gate.py`](.github/scripts/severity_gate.py)) y el archivo [`.github/security/excepciones.yml`](.github/security/excepciones.yml). Es una versión de un solo repositorio del diseño de 3.3: el archivo de excepciones vive en el mismo repo y está protegido por CODEOWNERS.

#### 3.5.1 Diferencia con dependency review

| | Dependency review | Gate de severidad mínima |
|---|---|---|
| Qué evalúa | Solo los **cambios** del PR | El **inventario completo** de los manifiestos de `demo/dependabot-severidad-minima/` |
| Criterio | Una severidad mínima (`fail-on-severity`) | Una **cantidad permitida por severidad**, más reglas por paquete y versión |
| Excepciones | `allow-ghsas` (solo por GHSA, sin vencimiento) | Por GHSA, paquete, rango de versiones y/o severidad, **con vencimiento** |
| Fuente | GitHub Advisory Database | GitHub Advisory Database (API pública, con `GITHUB_TOKEN`) |
| Funciona en ramas/PR | Sí | Sí (no depende de que las alertas de Dependabot existan en la rama predeterminada) |

#### 3.5.2 Orden de evaluación

Cada vulnerabilidad encontrada se clasifica en este orden:

1. **Excepción vigente** (`excepciones`): no cuenta para ningún umbral.
2. **Regla por paquete y versión** (`reglas_por_paquete`): se evalúa contra el umbral propio de la regla, que **reemplaza** al global para las severidades que define.
3. **Umbral global**: el resto se evalúa contra las variables del [workflow](.github/workflows/advanced-security.yml).

| Variable | Valor | Significado |
|---|---:|---|
| `MAX_CRITICAL` | `0` | Críticas permitidas |
| `MAX_HIGH` | `2` | Altas permitidas |
| `MAX_MEDIUM` | `15` | Medias permitidas |
| `MAX_LOW` | `-1` | Bajas permitidas (`-1` o vacío = sin límite) |
| `EXCEPTIONS_FILE` | `.github/security/excepciones.yml` | Excepciones y reglas por paquete |

El gate **falla** si se supera el umbral global, el de alguna regla, o si el archivo de excepciones es inválido.

#### 3.5.3 Cómo agregar una excepción de dependencias

La misma guía está junto a los archivos, en [`.github/security/README.md`](.github/security/README.md).

Archivo: [`.github/security/excepciones.yml`](.github/security/excepciones.yml) · Job: **Dependabot severidad mínima**

**Paso a paso**

1. **Identificar la vulnerabilidad.** En el PR, abrir el job *Dependabot severidad mínima* → *Summary* → tabla **Detalle**. Ahí están el `Paquete` (`nombre==versión`), la `Severidad` y el `Advisory` (ID GHSA).
2. **Intentar corregir primero**: subir la versión de la librería en el manifiesto. La excepción es el último recurso.
3. **Si no se puede corregir**, crear una rama y agregar una entrada en `excepciones.yml`:
   - bajo `excepciones:` para **aceptar** vulnerabilidades concretas (con vencimiento), o
   - bajo `reglas_por_paquete:` para darle a una librería un **cupo** propio de vulnerabilidades según su versión.
4. **Abrir un PR.** El gate valida el archivo: si falta un campo o no cumple la política, el job falla y lista los errores.
5. **Aprobación**: el PR requiere la revisión del code owner de `.github/security/` (CODEOWNERS). Con la aprobación y los checks en verde, se hace merge.
6. **Desde el merge**, el gate deja de contar lo que cubre la excepción: en la tabla **Detalle** aparece como *Exceptuada (`EXC-…`)* y la tabla **Control de excepciones** muestra su estado.
7. **Antes de que venza** (el job avisa 15 días antes): corregir la dependencia o **renovar** con un nuevo PR que actualice `vence` y `justificacion`. Cuando la vulnerabilidad se corrige, **borrar la entrada**; el gate avisa *"Vigente, sin coincidencias"* si queda una excepción que ya no cubre nada.

**Parámetros de una excepción** (lista `excepciones:`)

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la excepción en el resumen, en los avisos y en el historial de git | Código único en todo el archivo (no puede repetirse, tampoco con una regla). Convención: `EXC-AAAA-NNN` (año + correlativo) | `EXC-2026-004` |
| `paquete` | Sí, si no se indica `ghsa` | Limita la excepción a una librería | Nombre de la librería como está en el manifiesto. No distingue mayúsculas, guiones ni guiones bajos | `jinja2` |
| `ghsa` | Sí, si no se indica `paquete` | Limita la excepción a **una** vulnerabilidad | ID del advisory, columna *Advisory* del resumen | `GHSA-462w-v97r-4m45` |
| `versiones` | No | Limita la excepción a ciertas versiones de la librería | Rango de versiones de Python (PEP 440) **entre comillas**; varias condiciones separadas por coma. Si se omite, aplica a cualquier versión | `"==2.10"` · `">=2.0,<3.0"` |
| `severidades` | No | Limita la excepción a ciertas severidades | Lista con `high`, `medium` y/o `low`. **`critical` no se permite.** Si se omite, aplica a todas excepto `critical` | `[medium]` · `[high, medium]` |
| `justificacion` | Sí | Deja registrado por qué se acepta el riesgo | Texto **entre comillas** con el motivo concreto, la mitigación y el plan de corrección | `"El sandbox no se usa con plantillas de usuarios; migración a jinja2 3.x en el sprint 24."` |
| `solicitado_por` | No | Trazabilidad: quién pidió la excepción | Usuario de GitHub con `@`, entre comillas | `"@dev-backend"` |
| `aprobado_por` | Sí | Trazabilidad: quién aceptó el riesgo | Usuario del code owner que aprueba el PR, entre comillas. La aprobación efectiva es la revisión del PR | `"@RonnyTabangoBIT"` |
| `vence` | Sí | Hace que la excepción sea **temporal** | Fecha `AAAA-MM-DD` sin comillas, como máximo **hoy + 90 días**. La excepción se aplica hasta ese día incluido | `2027-01-31` |

La excepción se aplica solo si se cumplen **todas** las condiciones que se indiquen (`paquete`, `ghsa`, `versiones` y `severidades`). Combinaciones habituales:

| Quiero exceptuar… | Parámetros |
|---|---|
| Una vulnerabilidad puntual | `ghsa` |
| Una vulnerabilidad puntual, solo en la versión instalada | `ghsa` + `versiones` |
| Todas las vulnerabilidades de una librería, de cierta severidad, en una versión | `paquete` + `versiones` + `severidades` |

Ejemplos:

```yaml
excepciones:
  # Una vulnerabilidad puntual
  - id: EXC-2026-002
    ghsa: GHSA-462w-v97r-4m45
    justificacion: "Actualización a jinja2 3.x planificada para el próximo sprint."
    solicitado_por: "@RonnyTabangoBIT"
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2026-11-20

  # Todas las medias de una librería en una versión
  - id: EXC-2026-001
    paquete: jinja2
    versiones: "==2.10"
    severidades: [medium]
    justificacion: "El sandbox de Jinja2 no se usa con plantillas de usuarios."
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2027-01-31
```

**Parámetros de una regla por paquete** (lista `reglas_por_paquete:`)

Una regla no acepta vulnerabilidades concretas: le da a una librería un **cupo** propio por severidad, que reemplaza al umbral global (`MAX_*`) para esa librería. Sirve, por ejemplo, para tolerar más vulnerabilidades en versiones recientes que en versiones antiguas.

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la regla en el resumen | Código único en el archivo. Convención: `REG-NNN` | `REG-003` |
| `paquete` | Sí | Librería a la que aplica el cupo | Nombre como en el manifiesto | `requests` |
| `versiones` | Sí | Versiones a las que aplica el cupo | Rango PEP 440 entre comillas. Para cupos distintos por versión, crear varias reglas con rangos que **no se solapen** | `">=2.31.0"` |
| `max` | Sí | Cupo por severidad | Severidad y cantidad máxima (entero ≥ 0). Las severidades no listadas siguen el umbral global | `{ medium: 4 }` · `{ high: 1, medium: 4 }` |
| `justificacion` | Sí | Por qué se da ese cupo | Texto entre comillas | `"Versiones recientes: se toleran hasta 4 medias mientras se migra."` |

Las excepciones se evalúan **antes** que las reglas. Si varias reglas coinciden con la misma librería y versión, se usa la primera del archivo.

```yaml
reglas_por_paquete:
  - id: REG-001
    paquete: requests
    versiones: ">=2.31.0"
    max: { medium: 4 }
    justificacion: "Versiones recientes: se toleran hasta 4 medias mientras se migra."
  - id: REG-002
    paquete: requests
    versiones: "<2.31.0"
    max: { medium: 2 }
    justificacion: "Versiones antiguas: solo se toleran 2 medias."
```

**Política** (bloque `politica:`): la define el equipo de seguridad y **no se modifica al agregar una excepción**.

| Parámetro | Valor | Efecto |
|---|---|---|
| `max_dias_vigencia` | `90` | Ninguna excepción puede vencer después de hoy + 90 días |
| `aviso_dias_antes` | `15` | El job avisa cuando faltan 15 días o menos para el vencimiento |
| `permitir_excepcion_critical` | `false` | Las vulnerabilidades `critical` nunca se exceptúan: hay que corregirlas |

**Errores frecuentes** (el job falla y muestra el mensaje)

| Mensaje | Causa | Solución |
|---|---|---|
| ``falta `vence` `` (o `id`, `justificacion`, `aprobado_por`) | Falta un campo obligatorio | Agregar el campo |
| ``debe indicar `paquete` y/o `ghsa` `` | La excepción no dice qué cubre | Agregar `paquete`, `ghsa` o ambos |
| ``la política no permite exceptuar vulnerabilidades `critical` `` | Se puso `critical` en `severidades` | Quitarlo y corregir la dependencia |
| ``vence … supera el máximo de 90 días`` | La fecha es demasiado lejana | Usar una fecha dentro de los 90 días |
| ``vence inválido`` | Formato de fecha incorrecto | Usar `AAAA-MM-DD`, por ejemplo `2027-01-31` |
| ``versiones inválido`` | Rango mal escrito (por ejemplo `=>2.0`) | Usar `>=2.0`, `==2.10` o `>=2.0,<3.0` |
| ``id duplicado`` | El `id` ya existe en el archivo | Usar el siguiente correlativo |
| ``max.medium inválido`` | Cantidad negativa o severidad inexistente | Usar `critical`, `high`, `medium` o `low` con un entero ≥ 0 |

#### 3.5.4 Ejemplos configurados en la demo

| ID | Tipo | Alcance | Vence | Estado (al 2026-11-12) |
|---|---|---|---|---|
| `EXC-2026-001` | Excepción por librería | `jinja2 ==2.10`, solo `medium` (5 vulnerabilidades) | 2027-01-31 | ✅ Vigente |
| `EXC-2026-002` | Excepción por vulnerabilidad | `GHSA-462w-v97r-4m45` (la `high` de jinja2) | 2026-11-20 | ⏳ Vence en 8 días (aviso) |
| `EXC-2026-003` | Excepción por vulnerabilidad | `GHSA-9wx4-h78v-vm56` (una `medium` de requests) | 2026-10-31 | ⛔ Vencida: ya no se aplica |
| `REG-001` | Regla por versión | `requests >=2.31.0`: hasta 4 medias | — | ✅ 3 de 4 |
| `REG-002` | Regla por versión | `requests <2.31.0`: hasta 2 medias | — | No aplica a la versión instalada |

Resultado con el estado actual: de 9 vulnerabilidades, **6 exceptuadas**, **3 evaluadas por `REG-001`** y **0** contra el umbral global, así que el gate pasa con dos avisos.

Estados de una excepción en el resumen:

| Estado | Significado |
|---|---|
| ✅ Vigente | Se aplica |
| ⏳ Vence en N días | Se aplica, pero genera un aviso |
| ⚠️ Vigente, sin coincidencias | No cubre ninguna vulnerabilidad: revisar si sigue siendo necesaria |
| ⛔ Vencida | **Ya no se aplica**: la vulnerabilidad vuelve a contar |

#### 3.5.5 Resumen que publica el job

En *Actions → Summary* el job publica cuatro tablas:

1. **Umbral global**: por severidad, las encontradas, exceptuadas, evaluadas por regla, las que cuentan, las permitidas, el exceso y el estado.
2. **Reglas por paquete y versión**: versión instalada, encontradas y permitidas por regla.
3. **Control de excepciones**: alcance, vulnerabilidades cubiertas, vencimiento, estado, aprobador y justificación.
4. **Detalle**: cada vulnerabilidad con su tratamiento (*Exceptuada*, *Regla* o *Umbral global*) y si bloquea.

También deja anotaciones `::error` en la línea del manifiesto de cada vulnerabilidad que bloquea y `::warning` en el archivo de excepciones para las que están por vencer o vencidas.

#### 3.5.6 Cómo se aplica el flujo de 3.4 en este repo

| Paso de 3.4 | En este repositorio |
|---|---|
| 1. El gate bloquea | `Dependabot severidad mínima` falla y el ruleset de `main` impide el merge |
| 3. Solicitud | PR que agrega la entrada en `.github/security/excepciones.yml` |
| 3. Validación | El propio gate valida el archivo: campos, vencimiento máximo y política de `critical` |
| 4. Aprobación | `CODEOWNERS` asigna al code owner de `/.github/security/excepciones.yml` y el ruleset exige su revisión |
| 5. Aplicación | El siguiente run del gate excluye las vulnerabilidades cubiertas |
| 7. Vencimiento | Al vencer deja de aplicarse sola, el gate avisa y la vulnerabilidad vuelve a contar |
| 8. Auditoría | Historial de git de `excepciones.yml` y tabla *Control de excepciones* del resumen |

El paso 6 (sincronizar alertas de Dependabot) no está implementado en la demo: requiere un token con permiso `Dependabot alerts: write`.

#### 3.5.7 Escenarios de prueba

| Cambio | Resultado |
|---|---|
| Estado actual | ✅ Pasa, con avisos por `EXC-2026-002` (por vencer) y `EXC-2026-003` (vencida) |
| `requests==2.30.0` en `requirements.txt` | ❌ `REG-002`: 4 medias de 2 permitidas |
| Simular el vencimiento de `EXC-2026-002` (`GATE_TODAY=2026-11-25`) con `MAX_HIGH=0` | ❌ La alta de jinja2 vuelve a contar en el umbral global |
| Exceptuar una `critical`, `vence` a más de 90 días o campos faltantes | ❌ Archivo de excepciones inválido, con el detalle de cada error |

Para probar en local, desde la raíz del repo:

```bash
pip install packaging pyyaml
MAX_CRITICAL=0 MAX_HIGH=2 MAX_MEDIUM=15 python .github/scripts/severity_gate.py
GATE_TODAY=2026-11-25 MAX_HIGH=0 python .github/scripts/severity_gate.py   # simula el vencimiento
```

> A partir del 2026-11-20, `EXC-2026-002` queda vencida en los runs reales: la alta de jinja2 vuelve a contar en el umbral global. Con `MAX_HIGH: 2` el gate sigue pasando, pero el aviso cambia a "vencida".

### 3.6 Resumen de lo que se necesita

| Necesidad | Elemento |
|---|---|
| Umbral mínimo | `fail-on-severity` + `fail-on-scopes` en una configuración central, y/o un gate con cantidad permitida por severidad |
| Excepción puntual | `allow-ghsas`, generado desde `exceptions.yml` con vencimiento, o un gate propio con excepciones por GHSA, paquete, versión y severidad (como en 3.5) |
| Umbral distinto según la versión | Reglas por paquete y rango de versión en un gate propio (dependency review no lo soporta) |
| Exclusión de paquetes o licencias | `deny-packages`, `allow-dependencies-licenses` y `deny-licenses` |
| Gobierno y aprobación | Repositorio central + CODEOWNERS + ruleset |
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

1. **CodeQL detecta una alerta.**
2. **Autofix arma el prompt** con la descripción y la ayuda de la query de CodeQL, la ubicación y el flujo de datos (de la fuente al punto vulnerable) y los fragmentos de código relevantes, que pueden abarcar varios archivos.
3. **El modelo genera** un parche y una explicación.
4. **GitHub valida el parche**: que la sintaxis sea correcta y que aplique sobre el código.
5. **Se muestra como sugerencia** en el PR o en la alerta.

Además:

- El parche puede tocar **varios lugares de un archivo**, y a veces más de un archivo. También puede proponer **agregar una dependencia**, por ejemplo una librería de sanitización.
- El resultado **no es determinístico**: ejecutarlo dos veces sobre la misma alerta puede dar propuestas distintas, o ninguna.
- En los PRs, Autofix solo comenta las alertas **nuevas** que aparecen en **líneas modificadas por ese PR**. Las alertas que ya existían en la rama base se corrigen desde la alerta (*Generate fix*).
- GitHub declara que el código que se envía **no se usa para entrenar modelos** ni se retiene más allá de lo necesario para generar la sugerencia.

### 4.3 Cómo se usa

| Escenario | Flujo |
|---|---|
| **En Pull Requests** | Cuando CodeQL encuentra una alerta nueva en un PR, Autofix publica un comentario con la explicación y una **sugerencia de código**. El desarrollador puede *Commit suggestion*, editarla o descartarla |
| **Alertas existentes en la rama por defecto** | En *Security → Code scanning → alerta → **Generate fix***. Se revisa la propuesta y se elige **Create PR with fix** (o se abre en un Codespace para ajustarla) |
| **Security campaigns** | Se crea una campaña sobre un conjunto de alertas de la organización y Autofix genera correcciones en lote, que se pueden asignar a los responsables o al **agente de código de Copilot** para que abra los PRs (ver [4.7](#47-autofix-con-agente-security-campaigns-y-agente-de-código-de-copilot)) |
| **API REST** | `POST /repos/{o}/{r}/code-scanning/alerts/{n}/autofix` genera el fix, `GET` consulta su estado y `POST .../autofix/commits` lo commitea en una rama (ver [4.9](#49-prueba-en-este-repositorio-workflow-autofix-agent)) |
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
| `py/sql-injection` | `demo/codeql-code-scanning/app/app.py` (`/users`) | Pasar de concatenar strings a **consultas parametrizadas** (`cursor.execute("... WHERE name = ?", (name,))`) |
| `py/command-line-injection` | `demo/codeql-code-scanning/app/app.py` (`/ping`) | Usar `subprocess.run([...], shell=False)` con la lista de argumentos y validar el host |
| `py/reflective-xss` | `demo/codeql-code-scanning/app/app.py` (`/hello`) | Escapar la salida con `markupsafe.escape()` o usar plantillas con auto-escape |
| `py/path-injection` | `demo/codeql-code-scanning/app/app.py` (`/files`) | Usar `werkzeug.utils.safe_join` o normalizar la ruta y validar que quede dentro del directorio base |
| `py/flask-debug` | `demo/codeql-code-scanning/app/app.py` | Quitar `debug=True` o controlarlo con una variable de entorno |
| `py/unsafe-deserialization` | `demo/copilot-autofix/autofix_app.py` (`/profile`) | Reemplazar `pickle.loads` por `json.loads` |
| `py/weak-sensitive-data-hashing` | `demo/copilot-autofix/autofix_app.py` (`/register`) | Usar un KDF con salt (`hashlib.pbkdf2_hmac`, argon2) en lugar de `md5` |
| `py/url-redirection` | `demo/copilot-autofix/autofix_app.py` (`/login`) | Validar que `next` sea una URL relativa o del mismo host |
| `actions/code-injection` | `.github/workflows/advanced-security.yml` (paso *Mostrar commit*) | Mover `github.event.head_commit.message` a `env:` y referenciarlo como `"$COMMIT_MSG"` en el script |

### 4.6 Buenas prácticas

- Tratar Autofix como un **asistente**, no como una corrección automática: exigir revisión con CODEOWNERS (ver [sección 6](#6-gobierno-del-merge-rulesets-codeowners-y-aprobaciones)) y que los tests pasen.
- Combinarlo con el ruleset *Require code scanning results*, para que el PR no se pueda mergear hasta que la alerta desaparezca.
- Probar Autofix en **PRs dedicados**: un PR que introduce alertas nuevas a propósito queda bloqueado por *Require code scanning results* y no debería mezclarse con otros cambios que se quieran mergear.
- Medir el impacto en Security overview (alertas corregidas con Autofix, tiempo de remediación).
- Hacer seguimiento de los fixes que se descartan, porque suelen indicar falsos positivos o queries que conviene ajustar.

### 4.7 Autofix con agente: security campaigns y agente de código de Copilot

Además de las sugerencias individuales en PRs y alertas, GitHub permite **remediar alertas en lote** combinando dos piezas:

| Pieza | Qué hace | Nivel |
|---|---|---|
| **Security campaigns** | Agrupan un conjunto de alertas de code scanning de la organización (por ejemplo, *"todos los `py/sql-injection` de los repos de producción"*), con **fecha límite** y **responsables**. Para cada alerta de la campaña, Autofix genera la corrección propuesta | Organización (Code Security) |
| **Agente de código de Copilot** (Copilot coding agent) | Se le asigna una alerta (o un issue) y trabaja de forma autónoma: aplica el autofix o su propio cambio en una rama, ejecuta los tests en un entorno de GitHub Actions y **abre un Pull Request** para revisión | Organización / repositorio con licencia de Copilot |

**Flujo de remediación con agente:**

1. El equipo de seguridad (*security manager* u owner de la organización) crea una **campaña** desde *Organización → Security → Campaigns*, eligiendo las alertas por regla, severidad o repositorio, y define la fecha límite y los responsables.
2. Los responsables reciben la campaña con la corrección propuesta por Autofix para cada alerta.
3. Para cada alerta (o en lote), el responsable puede **crear un PR con el fix** o **asignarla al agente de Copilot**.
4. El agente crea una rama, aplica el cambio, ejecuta los workflows de CI y abre un PR. Las ejecuciones de workflows en PRs del agente pueden requerir aprobación manual (*Approve and run workflows*).
5. El PR pasa por el mismo control que cualquier cambio: **checks obligatorios, CodeQL y revisión de CODEOWNERS**. Quien pidió el trabajo al agente **no puede aprobar** su PR.
6. Al hacer merge, el siguiente análisis de CodeQL cierra la alerta y la campaña muestra el avance.

**Qué hace y qué no hace el agente:**

| Hace | No hace |
|---|---|
| Aplica correcciones en código y, si hace falta, agrega dependencias o ajusta tests | No hace merge: siempre deja un PR para revisión humana |
| Ejecuta los tests del repo antes de entregar | No garantiza que la corrección sea correcta ni completa |
| Responde a comentarios del PR con nuevos commits | No corrige dependencias vulnerables (Dependabot) ni secretos expuestos (hay que rotarlos) |

> Varias de estas capacidades (asignar alertas de campañas al agente, campañas de secret scanning) se publican primero en *preview*. Conviene confirmar su disponibilidad para el plan de la organización antes de planificar sobre ellas.

### 4.8 Requisitos para implementarlo en sus repositorios

| # | Requisito | Detalle | Cómo verificarlo |
|---|---|---|---|
| 1 | **Organización** | Security campaigns, el agente y las políticas centrales son funciones de organización; no existen en cuentas personales | *Your organizations* |
| 2 | **Licencia de Code Security** | Obligatoria en repositorios **privados**; en públicos, code scanning y Autofix son gratuitos | *Org → Settings → Billing and licensing* |
| 3 | **Code scanning con CodeQL** | Default setup o advanced setup (no ambos a la vez), con análisis recientes en la rama predeterminada. Autofix trabaja sobre alertas de la **rama predeterminada** | *Security → Code scanning*; workflow **Autofix Agent** (requisitos) |
| 4 | **Lenguaje soportado** | C#, C/C++, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift y workflows de GitHub Actions | Workflow **Autofix Agent** |
| 5 | **Copilot Autofix habilitado** | *Org → Settings → Code security → Global settings* y *Repo → Settings → Code security → Code scanning → Copilot Autofix* | Workflow **Autofix Agent** (la API responde 403 si está deshabilitado) |
| 6 | **Rol para campañas** | Owner de la organización o **security manager** | *Org → Settings → Roles* |
| 7 | **Licencia de Copilot** (solo para el agente) | Copilot Business o Enterprise, con la política del **coding agent** habilitada para la organización y el repositorio. **Autofix no la necesita**; el agente sí | *Org → Settings → Copilot → Policies* |
| 8 | **GitHub Actions habilitado** | El agente y los tests de validación corren en Actions (consumen minutos en repos privados) | *Repo → Settings → Actions* |
| 9 | **Tests automatizados** | Sin tests, un parche que compila puede cambiar el comportamiento sin que nadie lo note | Job `test` del workflow |
| 10 | **Gobierno del merge** | Ruleset con checks obligatorios, *Require code scanning results* y revisión de CODEOWNERS (ver [sección 6](#6-gobierno-del-merge-rulesets-codeowners-y-aprobaciones)) | *Settings → Rules* |

### 4.9 Prueba en este repositorio: workflow *Autofix Agent*

Como este repo es personal (sin campañas ni agente), el flujo se reproduce a nivel repositorio con la **API REST de Autofix** en el workflow [`autofix-agent.yml`](.github/workflows/autofix-agent.yml) y el script [`autofix_agent.py`](.github/scripts/autofix_agent.py):

| Paso | Endpoint |
|---|---|
| 1. Verificar requisitos (visibilidad, análisis de CodeQL, default setup, lenguajes) | `GET /repos/{r}`, `GET .../code-scanning/analyses`, `GET .../code-scanning/default-setup`, `GET .../languages` |
| 2. Seleccionar alertas abiertas de CodeQL con severidad >= `min_severity` | `GET .../code-scanning/alerts?state=open` |
| 3. Generar el autofix y esperar el resultado (`pending` → `success` / `error` / `outdated`) | `POST` y `GET .../code-scanning/alerts/{n}/autofix` |
| 4. (Opcional) Commitear los autofix en una rama `autofix/agente-<run>` | `POST .../code-scanning/alerts/{n}/autofix/commits` |
| 5. (Opcional) Abrir un PR de remediación para revisión | `POST .../pulls` |

Cómo ejecutarlo:

1. Hacer merge a `main` (un workflow con `workflow_dispatch` solo aparece si está en la rama predeterminada).
2. Habilitar *Settings → Actions → General →* ☑ **Allow GitHub Actions to create and approve pull requests** (para el PR).
3. *Actions → Autofix Agent → Run workflow*, con `min_severity`, `max_alerts` y `create_pr`.
4. Revisar el resumen: tabla de **requisitos** (✅ / ⚠️ / ❌) y tabla de **alertas procesadas** con el estado del autofix. Si `create_pr: true`, se abre un PR que pasa por el ruleset y CODEOWNERS como cualquier otro cambio.

El job falla si no se cumple algún requisito obligatorio (por ejemplo, code scanning sin análisis o Autofix deshabilitado). La lógica de selección de alertas y de requisitos tiene pruebas unitarias en [`test_autofix_agent.py`](.github/scripts/tests/test_autofix_agent.py), que corren en el job **Tests (scripts de seguridad)**.

> Los PRs creados con `GITHUB_TOKEN` **no disparan** otros workflows. Para que el PR del agente ejecute los checks, hay que cerrarlo y reabrirlo, hacer un push a la rama, o usar un token de GitHub App en lugar de `GITHUB_TOKEN`.

---

## 5. Excepciones de code scanning

Los hallazgos de CodeQL se controlan **igual que las dependencias** (sección 3.5): un archivo de excepciones versionado y protegido por CODEOWNERS, y un job que bloquea el merge si se supera el umbral. Esta es la **versión mínima** de la demo: el archivo es la **única forma** de aceptar un hallazgo.

### 5.1 Cómo funciona

1. **CodeQL analiza** el código en cada push y PR (job `codeql`) y genera los resultados (SARIF).
2. **El gate evalúa** cada hallazgo (job **Code scanning severidad mínima**, [`code_scanning_gate.py`](.github/scripts/code_scanning_gate.py)):
   - si tiene una **excepción vigente** en el archivo → no cuenta;
   - si su ruta tiene una **regla de umbral** → cuenta contra el umbral de esa regla;
   - si no → cuenta contra el **umbral global** (`MAX_*`).
3. Si algún umbral se supera, **el job falla** y el ruleset de `main` **bloquea el merge**.
4. Para aceptar un hallazgo que no se puede corregir, se agrega una **excepción por PR** en [`excepciones-codigo.yml`](.github/security/excepciones-codigo.yml). El PR requiere la aprobación del code owner. Al hacer merge, el gate la aplica sola; al **vencer**, deja de aplicarse y el hallazgo vuelve a contar.

### 5.2 Cómo agregar una excepción de código

La misma guía está junto a los archivos, en [`.github/security/README.md`](.github/security/README.md).

Archivo: [`.github/security/excepciones-codigo.yml`](.github/security/excepciones-codigo.yml) · Job: **Code scanning severidad mínima**

**Paso a paso**

1. **Identificar el hallazgo.** En el PR, abrir el job *Code scanning severidad mínima* → *Summary* → tabla **Detalle**. Ahí están la `Ubicación` (`ruta:línea`), la `Regla de CodeQL` y la `Severidad`.
2. **Intentar corregir primero**: corregir el código, por ejemplo con la sugerencia de Copilot Autofix. La excepción es el último recurso.
3. **Si no se puede corregir**, crear una rama y agregar una entrada en `excepciones-codigo.yml`:
   - bajo `excepciones:` para **aceptar** los hallazgos de una regla en una ruta (con vencimiento), o
   - bajo `reglas_por_ruta:` para darle a una carpeta un **cupo** propio de hallazgos.
4. **Abrir un PR.** El gate valida el archivo: si falta un campo o no cumple la política, el job falla y lista los errores.
5. **Aprobación**: el PR requiere la revisión del code owner de `.github/security/` (CODEOWNERS). Con la aprobación y los checks en verde, se hace merge.
6. **Desde el merge**, el gate deja de contar lo que cubre la excepción: en la tabla **Detalle** aparece como *Exceptuado (`EXC-COD-…`)*.
7. **Antes de que venza** (el job avisa 15 días antes): corregir el código o **renovar** con un nuevo PR que actualice `vence` y `justificacion`. Cuando el hallazgo se corrige, **borrar la entrada**.

No hace falta descartar la alerta en *Security → Code scanning*: el archivo es la única forma de aceptar un hallazgo.

**Parámetros de una excepción** (lista `excepciones:`)

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la excepción en el resumen, en los avisos y en el historial de git | Código único en todo el archivo (no puede repetirse, tampoco con una regla). Convención: `EXC-COD-AAAA-NNN` | `EXC-COD-2026-005` |
| `regla` | Sí | Indica **qué tipo de hallazgo** se acepta | ID de la regla de CodeQL, columna *Regla de CodeQL* del resumen o en la alerta. Distingue mayúsculas. Acepta `*` como comodín | `py/sql-injection` · `actions/code-injection/*` |
| `ruta` | Sí | Indica **en qué código** se acepta | Ruta desde la raíz del repo, sin `/` inicial; columna *Ubicación* sin el número de línea. Distingue mayúsculas. Acepta `*` (que también cruza carpetas). **No puede ser `*`, `**` ni `**/*`** (todo el repo) | `demo/app/app.py` · `demo/legacy/**` |
| `severidades` | No | Limita la excepción a ciertas severidades | Lista con `high`, `medium` y/o `low`. **`critical` no se permite.** Si se omite, aplica a todas excepto `critical` | `[medium, high]` |
| `justificacion` | Sí | Deja registrado por qué se acepta el riesgo | Texto **entre comillas** con el motivo concreto, la mitigación y el plan de corrección | `"El endpoint solo es accesible desde la VPN; se reescribe con consultas parametrizadas en el sprint 24."` |
| `solicitado_por` | No | Trazabilidad: quién pidió la excepción | Usuario de GitHub con `@`, entre comillas | `"@dev-backend"` |
| `aprobado_por` | Sí | Trazabilidad: quién aceptó el riesgo | Usuario del code owner que aprueba el PR, entre comillas. La aprobación efectiva es la revisión del PR | `"@RonnyTabangoBIT"` |
| `vence` | Sí | Hace que la excepción sea **temporal** | Fecha `AAAA-MM-DD` sin comillas, como máximo **hoy + 90 días**. La excepción se aplica hasta ese día incluido | `2027-01-31` |

La excepción se aplica solo si coinciden la `regla`, la `ruta` y, si se indican, las `severidades`. Conviene que la ruta sea **lo más acotada posible**: un archivo concreto mejor que una carpeta.

Ejemplos:

```yaml
excepciones:
  # Una regla en un archivo concreto
  - id: EXC-COD-2026-002
    regla: py/weak-sensitive-data-hashing
    ruta: demo/copilot-autofix/autofix_app.py
    justificacion: "Se deja para probar Copilot Autofix; corrección planificada con pbkdf2."
    solicitado_por: "@RonnyTabangoBIT"
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2026-11-20

  # Una familia de reglas, solo medium/high, en un archivo
  - id: EXC-COD-2026-003
    regla: actions/code-injection/*
    ruta: .github/workflows/advanced-security.yml
    severidades: [medium, high]
    justificacion: "Ejemplo intencional de code injection en workflows para CodeQL."
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2027-01-31
```

**Parámetros de una regla por ruta** (lista `reglas_por_ruta:`)

Una regla no acepta hallazgos concretos: le da a una carpeta un **cupo** propio por severidad, que reemplaza al umbral global (`MAX_*`) para esa carpeta. Sirve, por ejemplo, para código heredado o de demostración que se va a corregir de a poco.

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la regla en el resumen | Código único en el archivo. Convención: `REG-COD-NNN` | `REG-COD-003` |
| `ruta` | Sí | Código al que aplica el cupo | Ruta desde la raíz del repo, con comodín | `demo/**` · `legacy/**` |
| `regla` | No | Limita el cupo a ciertas reglas de CodeQL | ID de regla o patrón con `*`. Si se omite, aplica a todas (`*`) | `actions/code-injection/*` |
| `max` | Sí | Cupo por severidad | Severidad y cantidad máxima (entero ≥ 0). Las severidades no listadas siguen el umbral global | `{ critical: 2, high: 5, medium: 3 }` |
| `justificacion` | Sí | Por qué se da ese cupo | Texto entre comillas | `"Código de demostración vulnerable a propósito; no se despliega."` |

Las excepciones se evalúan **antes** que las reglas. Si varias reglas coinciden con el mismo hallazgo, se usa la primera del archivo.

```yaml
reglas_por_ruta:
  - id: REG-COD-001
    ruta: demo/**
    max: { critical: 2, high: 5, medium: 3 }
    justificacion: "Código de demostración vulnerable a propósito; no se despliega."
```

**Política** (bloque `politica:`): igual que en dependencias (90 días de vigencia máxima, aviso 15 días antes y `critical` no exceptuable). La define el equipo de seguridad y **no se modifica al agregar una excepción**.

**Severidad de un hallazgo**: es la que muestra GitHub según el `security-severity` de la regla de CodeQL: **critical** ≥ 9.0, **high** 7.0–8.9, **medium** 4.0–6.9, **low** < 4.0. Aparece en la columna *Severidad* del resumen, junto con el puntaje.

**Errores frecuentes** (el job falla y muestra el mensaje)

| Mensaje | Causa | Solución |
|---|---|---|
| ``falta `ruta` `` (o `id`, `regla`, `justificacion`, `aprobado_por`, `vence`) | Falta un campo obligatorio | Agregar el campo |
| ``ruta demasiado amplia`` | Se usó `*`, `**` o `**/*` | Indicar el archivo o la carpeta concreta |
| ``la política no permite exceptuar hallazgos `critical` `` | Se puso `critical` en `severidades` | Quitarlo y corregir el código |
| ``vence … supera el máximo de 90 días`` | La fecha es demasiado lejana | Usar una fecha dentro de los 90 días |
| ``vence inválido`` | Formato de fecha incorrecto | Usar `AAAA-MM-DD`, por ejemplo `2027-01-31` |
| ``id duplicado`` | El `id` ya existe en el archivo | Usar el siguiente correlativo |
| ``max.high inválido`` | Cantidad negativa o severidad inexistente | Usar `critical`, `high`, `medium` o `low` con un entero ≥ 0 |
| La excepción aparece como *"Vigente, sin coincidencias"* | La `regla` o la `ruta` no coinciden con ningún hallazgo (por ejemplo, mayúsculas distintas o ruta con `/` inicial) | Copiar la regla y la ruta tal como aparecen en la tabla **Detalle** |

**Excepciones y reglas configuradas en la demo** (al 2026-11-12):

| ID | Tipo | Alcance | Vence | Estado (al 2026-11-12) |
|---|---|---|---|---|
| `EXC-COD-2026-001` | Excepción | `py/flask-debug` en `demo/codeql-code-scanning/**` | 2027-01-31 | ✅ Vigente |
| `EXC-COD-2026-002` | Excepción | `py/weak-sensitive-data-hashing` en `autofix_app.py` | 2026-11-20 | ⏳ Vence pronto (aviso) |
| `EXC-COD-2026-003` | Excepción | `actions/code-injection/*` (medium/high) en el workflow | 2027-01-31 | ✅ Vigente |
| `EXC-COD-2026-004` | Excepción | `py/url-redirection` en `demo/copilot-autofix/**` | 2026-10-31 | ⛔ Vencida: ya no se aplica |
| `REG-COD-001` | Regla por ruta | `demo/**`: hasta 2 critical, 5 high y 3 medium | — | Presupuesto de las apps vulnerables |
| `REG-COD-002` | Regla por ruta | `.github/workflows/**`, `actions/code-injection/*`: hasta 1 critical | — | Por si CodeQL la clasifica critical |

### 5.3 Umbrales y severidad

| Variable (job en el workflow) | Valor | Aplica a |
|---|---:|---|
| `MAX_CRITICAL` | `0` | Hallazgos fuera de las reglas por ruta |
| `MAX_HIGH` | `0` | Ídem |
| `MAX_MEDIUM` | `2` | Ídem |
| `MAX_LOW` | `-1` (sin límite) | Ídem |

En la práctica: **cualquier hallazgo critical o high fuera de `demo/`** (por ejemplo, en `.github/scripts/`) bloquea el merge, y los de `demo/` solo bloquean si superan su presupuesto.

La severidad es la que muestra GitHub según el `security-severity` de la regla de CodeQL: **critical** ≥ 9.0, **high** 7.0–8.9, **medium** 4.0–6.9, **low** < 4.0.

Comparación con el gate de dependencias:

| | Dependencias | Code scanning |
|---|---|---|
| Job | `Dependabot severidad mínima` | `Code scanning severidad mínima` |
| Archivo | `excepciones.yml` | `excepciones-codigo.yml` |
| Excepción por | GHSA, paquete, versión, severidad | Regla de CodeQL + ruta, severidad |
| Umbral propio por | Paquete y versión | Ruta |
| Política | 90 días, aviso a 15 días, `critical` no exceptuable | Igual |

### 5.4 Pruebas

[`test_code_scanning_gate.py`](.github/scripts/tests/test_code_scanning_gate.py) usa SARIF simulados con la estructura de CodeQL ([`pruebas/sarif/`](.github/security/pruebas/sarif)) y corre en el job **Tests (scripts de seguridad)**:

| Escenario | Resultado |
|---|---|
| Estado actual de la demo | ✅ Pasa: 3 exceptuados, 6 dentro de `REG-COD-001` y avisos por las excepciones por vencer y vencida |
| Nuevo hallazgo critical en `.github/scripts/` | ❌ Umbral global: 1 de 0 críticas |
| Tercer hallazgo critical en `demo/` | ❌ `REG-COD-001`: 3 de 2 críticas |
| Vence `EXC-COD-2026-002` | ✅ La alta pasa a contar en `REG-COD-001` (3 de 5) |
| Archivo de excepciones inválido | ❌ Lista cada error |
| CodeQL no generó resultados | ❌ Falla |

Para probar en local, desde la raíz del repo:

```bash
pip install pyyaml
SARIF_DIR=.github/security/pruebas/sarif MAX_CRITICAL=0 MAX_HIGH=0 MAX_MEDIUM=2 python .github/scripts/code_scanning_gate.py
```

### 5.5 Ejecución con push a `main`

| Workflow | Disparo | Qué valida |
|---|---|---|
| **Advanced Security Demo** | Push a `main` y PRs | Tests, CodeQL, **gate de code scanning**, dependency review, **gate de dependencias** y tests de los scripts (en PRs, además, la aprobación automática) |
| **Autofix Agent** | Al terminar *Advanced Security Demo* en `main` (y de forma manual) | Requisitos de Autofix y autofix para las alertas `high`/`critical` |

### 5.6 Fuera de la versión mínima (para el producto final)

La versión mínima no controla lo que se hace **directamente en la interfaz de GitHub**. Para el producto final conviene evaluar:

| Tema | Qué es | Por qué importa |
|---|---|---|
| **Descartes en la interfaz** | Cualquier persona con permiso de escritura puede descartar una alerta (*False positive*, *Won't fix*, *Used in tests*) con un comentario | El gate no lo ve, pero la regla de ruleset *Require code scanning results* sí deja de bloquear. Por eso la versión mínima **no usa esa regla**: el gate es el único criterio |
| **Secret scanning** | Las alertas de secretos se cierran en la interfaz (*Revoked*, *False positive*, *Used in tests*, *Won't fix*) o con un bypass de push protection | No hay archivo ni gate para secretos: lo correcto es **rotar** el secreto (*Revoked*) |
| **Delegated alert dismissal** | El descarte pasa a ser una **solicitud** que aprueba el equipo de seguridad (queda en `dismissal_approved_by`) | Control preventivo nativo. Requiere **organización** |
| **Delegated bypass** | El bypass de push protection requiere la aprobación de una *bypass list* | Ídem. Requiere **organización** |
| **Trazabilidad** | Línea de tiempo de cada alerta, API (`dismissed_by`, `dismissed_reason`, `dismissed_comment`) y audit log de la organización | Permite auditar periódicamente los descartes hechos en la interfaz |

---

## 6. Gobierno del merge: rulesets, CODEOWNERS y aprobaciones

### 6.1 Ruleset sobre `main` (configuración de la demo)

En *Settings → Rules → Rulesets → New branch ruleset* (o importando el JSON del ruleset):

| Regla | Configuración |
|---|---|
| Enforcement status | **Active**, con la **bypass list vacía** (ni siquiera el admin se salta las reglas) |
| Target | **Include default branch** |
| Restrict deletions / Block force pushes | ☑ |
| Require a pull request before merging | **Required approvals: 1**; ☑ *Require review from Code Owners* (ver 6.4 y 6.5); *Require approval of the most recent reviewable push* ☐; *Require conversation resolution* ☑ |
| Require status checks to pass | ☑ *Require branches to be up to date*; checks con origen **GitHub Actions**: `Dependabot severidad mínima`, `Code scanning severidad mínima`, `Dependency Review`, `CodeQL (python)`, `CodeQL (actions)`, `Tests (codeql-code-scanning)`, `Tests (copilot-autofix)` y `Tests (scripts de seguridad)` |
| Require code scanning results | ☐ **No se usa en la versión mínima**: respeta los descartes hechos en la interfaz. El criterio para los hallazgos de código es el gate `Code scanning severidad mínima` (ver [5.6](#56-fuera-de-la-versión-mínima-para-el-producto-final)) |

Puntos a tener en cuenta:

- Los status checks solo aparecen en el buscador del ruleset si se ejecutaron en los **últimos 7 días**.
- El nombre del check debe coincidir **exactamente** con el `name:` del job (incluidos acentos). Si se renombra el job, el PR queda esperando un check que nunca llega (*"Expected — Waiting for status to be reported"*).

### 6.2 ¿Qué es CODEOWNERS?

Es un archivo que define **quién es responsable de revisar cada parte del repositorio**. Cuando un PR modifica archivos de una ruta, GitHub:

1. **Asigna como reviewers** a los dueños de esa ruta, de forma automática.
2. Si el ruleset tiene **Require review from Code Owners**, **bloquea el merge** hasta que apruebe uno de los dueños de cada ruta modificada.

### 6.3 Crear el grupo de aprobadores

Cómo se define el "grupo" depende de quién es dueño del repositorio:

| | Repositorio personal | Repositorio de organización |
|---|---|---|
| Qué es un "grupo" | Una **lista de usuarios** en la misma línea de `CODEOWNERS` | Un **team** (`@org/team`) |
| Dónde se crea | Directamente en el archivo `CODEOWNERS` | Organización → **Teams** → **New team** |
| Requisito | Que cada usuario sea **colaborador** del repositorio (siempre con permiso Write) | Que el team tenga permiso **Write** sobre el repositorio |
| Asignación automática | Se piden todos los de la lista | El team puede asignar **N miembros** por *round robin* o por carga |

**Opción A – Repositorio personal (lista de usuarios)**

1. *Settings → Collaborators → Add people*: invitar a cada aprobador y esperar a que **acepte** la invitación. Hasta entonces su aprobación no cuenta.
2. Escribir la lista en `CODEOWNERS`, por ejemplo `/demo/  @usuario1 @usuario2`. Basta con la aprobación de **uno** de la lista.

**Opción B – Organización (team)**

1. Crear una organización gratuita: avatar → **Your organizations** → **New organization** → plan **Free**.
2. Transferir el repositorio: *Settings → General → Danger Zone → Transfer ownership*.
3. Crear el team: organización → **Teams** → **New team** (por ejemplo, `aprobadores-seguridad`) y agregar los miembros.
4. Dar acceso: en el repositorio, *Settings → Collaborators and teams → Add teams* → rol **Write**.
5. (Opcional) Asignación automática: team → *Settings → Code review* → **Enable auto assignment**, con la cantidad de revisores (por ejemplo `1`) y el algoritmo (*Round robin* o *Load balance*).

### 6.4 Archivo `CODEOWNERS`

Ubicación: `.github/CODEOWNERS` (también se acepta en la raíz o en `docs/`). Este es el archivo de esta demo ([`.github/CODEOWNERS`](.github/CODEOWNERS)); en un equipo real, cada ruta tendría a otra persona o a un team (por ejemplo `@mi-org/aprobadores-seguridad`):

```
# =====================================================================================
# CODEOWNERS – Demo GitHub Advanced Security
# Formato: <patrón de ruta>  <dueño1> <dueño2> ...   (basta la aprobación de UNO de la línea)
# La ÚLTIMA regla que coincide con un archivo es la que aplica.
# En un repo personal los dueños son usuarios colaboradores; en una organización, teams (@org/team).
# Para que bloquee el merge: ruleset de main -> "Require review from Code Owners".
# =====================================================================================

# Dueño por defecto de todo el repositorio
*                                         @RonnyTabangoBIT

# Workflows, Dependabot y scripts de seguridad (umbrales MAX_*)
/.github/                                 @RonnyTabangoBIT

# Control de excepciones y gate de severidad mínima: aprobador de seguridad
/.github/security/excepciones.yml         @RonnyTabangoBIT
/.github/security/excepciones-codigo.yml  @RonnyTabangoBIT
/.github/scripts/severity_gate.py         @RonnyTabangoBIT
/.github/scripts/code_scanning_gate.py    @RonnyTabangoBIT
/demo/dependabot-severidad-minima/        @RonnyTabangoBIT

# Demos de code scanning, Autofix y dependency review
/demo/codeql-code-scanning/               @RonnyTabangoBIT
/demo/copilot-autofix/                    @RonnyTabangoBIT
/demo/dependency-review/                  @RonnyTabangoBIT

# Este mismo archivo: nadie puede cambiar los dueños sin aprobación
/.github/CODEOWNERS                       @RonnyTabangoBIT
```

| Patrón | Qué cubre |
|---|---|
| `*` | Todo el repositorio |
| `/demo/` | La carpeta `demo/` de la raíz y todo su contenido |
| `*.yml` | Todos los `.yml` en cualquier carpeta |
| `/.github/scripts/severity_gate.py` | Un archivo concreto |
| `@usuario`, `@org/team`, `correo@dominio.com` | Tipos de dueño válidos |

- **Gana la última coincidencia**: las reglas generales van arriba y las específicas abajo.
- Proteger `/.github/` es importante: si no, cualquiera podría subir `MAX_HIGH: 999` en el workflow y mergearlo sin la aprobación de seguridad.
- Proteger `/.github/security/excepciones.yml` y `/.github/security/excepciones-codigo.yml` hace que **ninguna excepción ni regla de cupo** entre sin la aprobación del code owner: es la pieza de aprobación del flujo de 3.4 y de la sección 5.
- Proteger el propio `/.github/CODEOWNERS` evita que alguien cambie los dueños para saltarse la revisión.
- Al abrir el archivo en GitHub se muestran advertencias si hay usuarios sin acceso o errores de sintaxis.

Para que CODEOWNERS bloquee el merge, se activa en el ruleset *Require a pull request before merging* → ☑ **Require review from Code Owners** (en JSON: `"require_code_owner_review": true`).

Qué se ve en el PR:

- **Reviewers**: los code owners aparecen solicitados automáticamente, con un ícono de escudo.
- **Files changed**: cada archivo indica su dueño (*"Owned by @usuario"*).
- **Caja de merge**: *"Review required — Waiting on code owner review from @usuario"* hasta que uno apruebe.

### 6.5 Limitación: el autor no puede aprobar su propio PR

GitHub **no cuenta la aprobación del autor del PR**, tampoco como code owner. Copilot code review solo comenta y tampoco cuenta como aprobación. Por eso, en un repositorio con una sola persona:

| Configuración | Resultado |
|---|---|
| CODEOWNERS solo con el autor + *Require review from Code Owners* (**configuración actual de la demo**) | ❌ El merge queda en *"Review required — Waiting on code owner review"*: el autor no puede aprobar y el bot de Actions **no puede** ser code owner. Sirve para mostrar el mensaje del aprobador |
| CODEOWNERS solo con el autor, regla desactivada + aprobación automática (6.6) | ✅ Funciona: CODEOWNERS muestra la asignación de dueños y el bot da la aprobación requerida |
| CODEOWNERS con un **segundo usuario** + regla activada | ✅ Es el flujo real: el compañero aprueba como code owner |

### 6.6 Aprobación automática (solo para la demo)

Para validar el flujo de aprobación sin un segundo revisor, el workflow tiene el job **Aprobación automática** (`auto-approve`):

- Se ejecuta solo en `pull_request` y depende (`needs`) de `test`, `codeql`, `dependency-review` y `dependabot-severity-gate`. **Si alguno falla, no se ejecuta** y el PR queda sin aprobación.
- Si el autor del PR está en la variable `APROBADORES` (el "grupo de aprobadores", usuarios separados por espacio), `github-actions[bot]` aprueba el PR con `gh pr review --approve`.
- Requiere habilitar *Settings → Actions → General → Workflow permissions →* ☑ **Allow GitHub Actions to create and approve pull requests**.
- El mensaje de la aprobación indica el grupo de aprobadores y recuerda que las rutas protegidas por CODEOWNERS siguen requiriendo la revisión del code owner.
- La aprobación del bot cubre *Required approvals: 1*, pero **no** la revisión de code owner.

Flujo resultante del PR:

1. Se abre el PR y corren los checks del workflow. CODEOWNERS asigna al aprobador de las rutas modificadas.
2. Si algún check falla (por ejemplo, se supera `MAX_HIGH` o el archivo de excepciones es inválido), el merge queda bloqueado por el check en rojo **y** por la falta de aprobación.
3. Si todos pasan, el bot aprueba. Con *Require review from Code Owners* activado, el merge sigue esperando al code owner (*"Waiting on code owner review"*); si se desactiva esa opción, el merge queda habilitado.

> En un entorno real esto **no reemplaza la revisión humana**: lo correcto es tener al menos un segundo revisor (colaborador o team en CODEOWNERS) con *Require review from Code Owners* activado.

---

## 7. Referencias

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
- REST API, Global security advisories: <https://docs.github.com/en/rest/security-advisories/global-advisories>
- Reusable workflows: <https://docs.github.com/en/actions/sharing-automations/reusing-workflows>
- Rulesets, required workflows y code scanning: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>
- REST API, Autofix de code scanning: <https://docs.github.com/en/rest/code-scanning/code-scanning#get-the-status-of-an-autofix-for-a-code-scanning-alert>
- Copilot coding agent: <https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-coding-agent>
- Dismissing code scanning alerts: <https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/resolving-code-scanning-alerts>
- Delegated alert dismissal: <https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/enabling-delegated-alert-dismissal-for-code-scanning>
- Resolving secret scanning alerts: <https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning/resolving-alerts>
- Delegated bypass for push protection: <https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/delegated-bypass-for-push-protection>
- Audit log events for your organization: <https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization>
- About code owners: <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners>
- Managing code review settings for your team: <https://docs.github.com/en/organizations/organizing-members-into-teams/managing-code-review-settings-for-your-team>
- Managing GitHub Actions settings (aprobar PRs desde Actions): <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository>
- WeasyPrint: <https://doc.courtbouillon.org/weasyprint/>
