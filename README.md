# BIT-DEVOPS-DEMO-SCAN-AVANCED-SECURITY

Demo app (Flask) **intencionalmente vulnerable** para probar GitHub Advanced Security con GitHub Actions.

> ⚠️ No desplegar. El código contiene vulnerabilidades a propósito.

## Estructura

| Ruta | Descripción |
|------|-------------|
| `app/app.py` | API Flask con endpoints vulnerables (SQLi, command injection, XSS, path traversal, debug=True) |
| `tests/` | Tests con pytest |
| `requirements.txt` | 2 dependencias: `flask==3.1.3` (válida) y `urllib3==1.26.4` (CVE-2021-33503, muestra el fallo) |
| `.github/workflows/advanced-security.yml` | Workflow único con los jobs `test`, `codeql` (Python + Actions) y `dependency-review`. Usa `actions/download-artifact@v4.1.2` (CVE-2024-42471) como acción vulnerable |
| `.github/dependabot.yml` | Actualizaciones de pip y GitHub Actions |

## Ejecutar localmente

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt pytest   # Windows: .venv\Scripts\pip
python -m pytest
python -m app.app
```

## Flujo de prueba

1. Habilitar en **Settings → Code security**: Dependency graph, Dependabot alerts, Secret scanning / Push protection
   (en repos privados se requiere licencia de GitHub Advanced Security / Code Security).
2. Hacer push (o merge) a `main`: el workflow solo se ejecuta en push a `main`.
3. En **Actions**, el job `dependency-review` falla por `urllib3==1.26.4` y `actions/download-artifact@v4.1.2` (severidad alta); `test` y `codeql` terminan OK.
4. Cada job publica un resumen (tests, alertas CodeQL y dependencias vulnerables, indicando si hubo errores) en la página **Summary** de la ejecución.
5. Ver las alertas en **Security → Code scanning** y **Security → Dependabot**.

## Alertas esperadas (CodeQL)

- `py/sql-injection` – `/users`
- `py/command-line-injection` – `/ping`
- `py/reflective-xss` – `/hello`
- `py/path-injection` – `/files`
- `py/flask-debug` – `app.run(debug=True)`
- `actions/code-injection` – paso `Mostrar commit` en `advanced-security.yml` (`github.event.head_commit.message` en `run`)

