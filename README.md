# BIT-DEVOPS-DEMO-SCAN-AVANCED-SECURITY

Demo app (Flask) **intencionalmente vulnerable** para probar GitHub Advanced Security con GitHub Actions.

> ⚠️ No desplegar. El código contiene vulnerabilidades a propósito.

## Estructura

| Ruta | Descripción |
|------|-------------|
| `app/app.py` | API Flask con endpoints vulnerables (SQLi, command injection, XSS, path traversal, debug=True) |
| `tests/` | Tests con pytest |
| `requirements.txt` | Dependencias con versiones antiguas con CVEs conocidos |
| `.github/workflows/codeql.yml` | Code scanning con CodeQL (Python + Actions, queries `security-extended`) |
| `.github/workflows/dependency-review.yml` | Bloquea PRs que introducen dependencias vulnerables (severidad alta) |
| `.github/workflows/ci.yml` | Ejecuta los tests |
| `.github/dependabot.yml` | Actualizaciones de pip y GitHub Actions |

## Ejecutar localmente

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
python -m pytest
python -m app.app
```

Requiere Python ≤ 3.11 por las versiones antiguas de Werkzeug.

## Flujo de prueba

1. Habilitar en **Settings → Code security**: Dependency graph, Dependabot alerts, Secret scanning / Push protection
   (en repos privados se requiere licencia de GitHub Advanced Security / Code Security).
2. Crear una rama, hacer push y abrir un Pull Request hacia `main`.
3. Revisar en el PR los checks **CodeQL** y **Dependency Review**, y las anotaciones de código.
4. Tras el merge, ver las alertas en **Security → Code scanning** y **Security → Dependabot**.

## Alertas esperadas (CodeQL)

- `py/sql-injection` – `/users`
- `py/command-line-injection` – `/ping`
- `py/reflective-xss` – `/hello`
- `py/path-injection` – `/files`
- `py/flask-debug` – `app.run(debug=True)`
