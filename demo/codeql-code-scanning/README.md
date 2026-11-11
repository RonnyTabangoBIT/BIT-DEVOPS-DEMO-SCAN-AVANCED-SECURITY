# CodeQL – Code scanning

API Flask **intencionalmente vulnerable** analizada por el job `codeql` (Python + Actions) del workflow
[`advanced-security.yml`](../../.github/workflows/advanced-security.yml).

## Ejecutar localmente

```bash
cd demo/codeql-code-scanning
python -m venv .venv
.venv/bin/pip install -r requirements.txt pytest   # Windows: .venv\Scripts\pip
python -m pytest
python -m app.app
```

## Alertas esperadas

| Regla | Ubicación |
|-------|-----------|
| `py/sql-injection` | `/users` |
| `py/command-line-injection` | `/ping` |
| `py/reflective-xss` | `/hello` |
| `py/path-injection` | `/files` |
| `py/flask-debug` | `app.run(debug=True)` |
| `actions/code-injection` | paso `Mostrar commit` de `advanced-security.yml` (`github.event.head_commit.message` en `run`) |

Ver en **Security → Code scanning**.
