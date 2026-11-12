"""Agente de remediación con Copilot Autofix (demo).

Usa la API REST de code scanning para:
  1. Verificar los requisitos de Autofix en el repositorio.
  2. Seleccionar alertas abiertas de CodeQL de la rama predeterminada con severidad >= MIN_SEVERITY.
  3. Pedir un autofix para cada alerta y esperar el resultado (pending -> success | error | outdated).
  4. (Opcional) Commitear los autofix generados en una rama nueva y abrir un Pull Request para revisión.

Es el equivalente, a nivel repositorio, de "security campaigns + agente de Copilot": genera las correcciones
en lote, pero siempre las entrega como PR para que un humano las revise (CODEOWNERS + ruleset).

Variables de entorno:
  GITHUB_TOKEN        token con security-events: write, contents: write, pull-requests: write
  GITHUB_REPOSITORY   owner/repo
  MIN_SEVERITY        low | medium | high | critical            por defecto: high
  MAX_ALERTS          máximo de alertas a procesar              por defecto: 5
  CREATE_PR           true | false                              por defecto: false
  POLL_SECONDS        tiempo máximo de espera por alerta        por defecto: 180
  GITHUB_STEP_SUMMARY archivo de resumen de Actions (si no existe, se imprime en stdout)
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# Lenguajes que CodeQL analiza (nombres de GET /repos/{r}/languages). Los workflows de Actions también se analizan.
CODEQL_LANGUAGES = {"Python", "JavaScript", "TypeScript", "Java", "Kotlin", "C#", "Go", "Ruby", "Swift", "C", "C++"}


class Api:
    def __init__(self, token, repo):
        self.token, self.repo = token, repo

    def call(self, method, path, body=None):
        url = path if path.startswith("http") else f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {self.token}",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as err:
            raw = err.read()
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = {"message": raw.decode(errors="replace")}
            return err.code, payload

    def repo_path(self, suffix=""):
        return f"/repos/{self.repo}{suffix}"


def message(payload):
    return (payload or {}).get("message", "") if isinstance(payload, dict) else ""


# ------------------------------------------------------------------------------- lógica pura (testeable)

def select_alerts(alerts, min_severity, max_alerts):
    """Alertas abiertas de CodeQL con severidad de seguridad >= min_severity, de mayor a menor severidad."""
    threshold = RANK[min_severity]
    selected = [
        a for a in alerts
        if a.get("state") == "open"
        and (a.get("tool") or {}).get("name") == "CodeQL"
        and RANK.get((a.get("rule") or {}).get("security_severity_level") or "", 0) >= threshold
    ]
    selected.sort(key=lambda a: (-RANK.get(a["rule"].get("security_severity_level") or "", 0), a["number"]))
    return selected[:max_alerts]


def location(alert):
    loc = ((alert.get("most_recent_instance") or {}).get("location") or {})
    return f"{loc.get('path', '?')}:{loc.get('start_line', '?')}"


def requirement(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def evaluate_requirements(repo_info, analyses_status, default_setup, languages):
    """Devuelve la lista de requisitos con estado ✅ / ⚠️ / ❌.

    repo_info: JSON de GET /repos/{r}; analyses_status: (status, payload) de GET code-scanning/analyses;
    default_setup: (status, payload) de GET code-scanning/default-setup; languages: dict de GET /languages.
    """
    reqs = []
    visibility = (repo_info or {}).get("visibility", "desconocida")
    if visibility == "public":
        reqs.append(requirement("Licencia", "✅", "Repositorio público: code scanning y Autofix gratuitos"))
    else:
        reqs.append(requirement("Licencia", "⚠️", f"Repositorio {visibility}: requiere GitHub Code Security en una organización"))

    status, payload = analyses_status
    if status == 200 and payload:
        reqs.append(requirement("Code scanning con CodeQL", "✅", f"Último análisis: {payload[0].get('created_at', '?')}"))
    elif status == 200:
        reqs.append(requirement("Code scanning con CodeQL", "❌", "No hay análisis: ejecutar el workflow de CodeQL"))
    else:
        reqs.append(requirement("Code scanning con CodeQL", "❌", f"No disponible ({status}): {message(payload)}"))

    status, payload = default_setup
    if status == 200:
        state = (payload or {}).get("state")
        if state == "configured":
            reqs.append(requirement("Modo de configuración", "⚠️", "Default setup activo: entra en conflicto con el workflow (advanced setup)"))
        else:
            reqs.append(requirement("Modo de configuración", "✅", "Advanced setup (workflow propio)"))
    else:
        reqs.append(requirement("Modo de configuración", "⚠️", f"No verificable con este token ({status}); requiere permiso Administration: read"))

    found = sorted(set(languages or {}) & CODEQL_LANGUAGES)
    if found:
        reqs.append(requirement("Lenguajes soportados", "✅", ", ".join(found) + " (+ workflows de GitHub Actions)"))
    else:
        reqs.append(requirement("Lenguajes soportados", "⚠️", "Ningún lenguaje compatible detectado; solo workflows de Actions"))
    return reqs


# ------------------------------------------------------------------------------- flujo con la API

def wait_autofix(api, number, timeout):
    deadline = time.monotonic() + timeout
    status, payload = api.call("POST", api.repo_path(f"/code-scanning/alerts/{number}/autofix"))
    if status not in (200, 202):
        return "error", f"No se pudo solicitar ({status}): {message(payload)}"
    while True:
        state = (payload or {}).get("status")
        if state in ("success", "error", "outdated"):
            return state, (payload or {}).get("description") or ""
        if time.monotonic() > deadline:
            return "timeout", "El autofix sigue en estado pending"
        time.sleep(10)
        status, payload = api.call("GET", api.repo_path(f"/code-scanning/alerts/{number}/autofix"))
        if status != 200:
            return "error", f"Error al consultar ({status}): {message(payload)}"


def main():
    token, repo = os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        sys.exit("Se requieren GITHUB_TOKEN y GITHUB_REPOSITORY")
    min_severity = os.environ.get("MIN_SEVERITY", "high").lower()
    if min_severity not in RANK:
        sys.exit(f"MIN_SEVERITY inválido: {min_severity}")
    max_alerts = int(os.environ.get("MAX_ALERTS", "5"))
    create_pr = os.environ.get("CREATE_PR", "false").lower() == "true"
    poll = int(os.environ.get("POLL_SECONDS", "180"))
    api = Api(token, repo)

    _, repo_info = api.call("GET", api.repo_path())
    default_branch = (repo_info or {}).get("default_branch", "main")
    reqs = evaluate_requirements(
        repo_info,
        api.call("GET", api.repo_path("/code-scanning/analyses?per_page=1")),
        api.call("GET", api.repo_path("/code-scanning/default-setup")),
        api.call("GET", api.repo_path("/languages"))[1],
    )

    alerts, url = [], api.repo_path("/code-scanning/alerts?state=open&per_page=100")
    status, payload = api.call("GET", url)
    if status == 200:
        alerts = payload or []
    selected = select_alerts(alerts, min_severity, max_alerts)

    results = []
    for alert in selected:
        state, description = wait_autofix(api, alert["number"], poll)
        results.append({"alert": alert, "state": state, "description": description, "commit": ""})

    if results and all(r["state"] == "error" and "(403)" in r["description"] for r in results):
        reqs.append(requirement("Copilot Autofix habilitado", "❌", results[0]["description"]))
    elif results:
        reqs.append(requirement("Copilot Autofix habilitado", "✅", "La API generó o intentó generar autofixes"))
    else:
        reqs.append(requirement("Copilot Autofix habilitado", "⚠️", "Sin alertas seleccionadas: no se pudo verificar"))

    pr_url, branch = "", ""
    fixed = [r for r in results if r["state"] == "success"]
    if create_pr and fixed:
        branch = f"autofix/agente-{os.environ.get('GITHUB_RUN_ID', int(time.time()))}"
        _, ref = api.call("GET", api.repo_path(f"/git/ref/heads/{default_branch}"))
        base_sha = ((ref or {}).get("object") or {}).get("sha")
        status, payload = api.call("POST", api.repo_path("/git/refs"), {"ref": f"refs/heads/{branch}", "sha": base_sha})
        if status != 201:
            sys.exit(f"No se pudo crear la rama {branch} ({status}): {message(payload)}")
        for r in fixed:
            alert = r["alert"]
            status, payload = api.call("POST", api.repo_path(f"/code-scanning/alerts/{alert['number']}/autofix/commits"), {
                "target_ref": f"refs/heads/{branch}",
                "message": f"fix: Autofix para alerta #{alert['number']} ({alert['rule']['id']})",
            })
            r["commit"] = (payload or {}).get("sha", "")[:7] if status in (200, 201) else f"error {status}"
        committed = [r for r in fixed if r["commit"] and not r["commit"].startswith("error")]
        if committed:
            body = ["## 🤖 Remediación con Copilot Autofix", "",
                    "PR generado por el workflow **Autofix Agent**. **Revisar cada cambio antes de aprobar**: "
                    "Autofix es una sugerencia, no una corrección garantizada.", "",
                    "| Alerta | Regla | Severidad | Ubicación | Commit |", "|---|---|---|---|---|"]
            for r in committed:
                a = r["alert"]
                body.append(f"| [#{a['number']}]({a['html_url']}) | `{a['rule']['id']}` | "
                            f"{a['rule'].get('security_severity_level')} | `{location(a)}` | {r['commit']} |")
            status, payload = api.call("POST", api.repo_path("/pulls"), {
                "title": f"Autofix: {len(committed)} alerta(s) de code scanning",
                "head": branch, "base": default_branch, "body": "\n".join(body),
            })
            pr_url = (payload or {}).get("html_url", "") if status == 201 else f"error {status}: {message(payload)}"
        else:
            api.call("DELETE", api.repo_path(f"/git/refs/heads/{branch}"))
            branch = ""

    out = ["## 🤖 Autofix Agent", "",
           f"- **Repositorio:** `{repo}` (rama predeterminada `{default_branch}`)",
           f"- **Filtro:** alertas abiertas de CodeQL con severidad >= `{min_severity}`, máximo {max_alerts}.",
           f"- **Alertas abiertas:** {len(alerts)} — seleccionadas: **{len(selected)}** — con autofix: **{len(fixed)}**.",
           "", "### Requisitos", "", "| Requisito | Estado | Detalle |", "|---|---|---|"]
    out += [f"| {r['name']} | {r['status']} | {r['detail']} |" for r in reqs]
    out.append("")
    if results:
        out += ["### Alertas procesadas", "",
                "| Alerta | Regla | Severidad | Ubicación | Autofix | Commit | Descripción |",
                "|---|---|---|---|---|---|---|"]
        icons = {"success": "✅ success", "error": "❌ error", "outdated": "⚠️ outdated", "timeout": "⏳ timeout"}
        for r in results:
            a = r["alert"]
            desc = r["description"].replace("|", "\\|").replace("\n", " ")[:200]
            out.append(f"| [#{a['number']}]({a['html_url']}) | `{a['rule']['id']}` | {a['rule'].get('security_severity_level')} | "
                       f"`{location(a)}` | {icons.get(r['state'], r['state'])} | {r['commit'] or '—'} | {desc} |")
        out.append("")
    if create_pr:
        out.append(f"**Pull Request:** {pr_url or 'no se creó (ningún autofix pudo commitearse)'}")
    else:
        out.append("**Modo solo lectura:** ejecutar con `create_pr: true` para commitear los autofix en una rama y abrir un PR.")

    text = "\n".join(out)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if any(r["status"] == "❌" for r in reqs):
        print("::error::No se cumplen los requisitos de Copilot Autofix (ver resumen).")
        sys.exit(1)


if __name__ == "__main__":
    main()
