"""Auditoría de excepciones de code scanning y secret scanning (demo).

Lee las alertas DESCARTADAS de code scanning y RESUELTAS de secret scanning por API, las valida contra
.github/security/politica-descartes.yml y publica un registro de trazabilidad:
quién descartó, cuándo, con qué motivo, con qué justificación, quién aprobó (delegated dismissal) y si cumple.

Variables de entorno:
  GITHUB_TOKEN          token con security-events: read (code scanning)
  SECURITY_AUDIT_TOKEN  opcional: fine-grained PAT con "Secret scanning alerts: Read" (GITHUB_TOKEN no puede leerlas)
  GITHUB_REPOSITORY     owner/repo
  POLICY_FILE           por defecto: .github/security/politica-descartes.yml
  AUDIT_CSV             archivo CSV de salida (registro de trazabilidad)   por defecto: registro-excepciones.csv
  GATE_TODAY            fecha de evaluación AAAA-MM-DD (opcional, para pruebas)
  GITHUB_STEP_SUMMARY   archivo de resumen de Actions (si no existe, se imprime en stdout)
"""
import csv
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

API = "https://api.github.com"


# ------------------------------------------------------------------------------- lógica pura (testeable)

def parse_ts(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def login(user):
    return (user or {}).get("login", "") if isinstance(user, dict) else ""


def _common_checks(reason, comment, actor, cfg, allowed_key, id_regex):
    problems = []
    allowed = cfg.get(allowed_key) or []
    if allowed and reason not in allowed:
        problems.append(f"motivo `{reason}` no permitido")
    if len((comment or "").strip()) < int(cfg.get("comentario_minimo", 0)):
        problems.append(f"justificación menor a {cfg.get('comentario_minimo')} caracteres")
    if reason in (cfg.get("requiere_id_excepcion") or []) and not re.search(id_regex, comment or ""):
        problems.append("falta el ID de excepción en el comentario")
    approvers = cfg.get("aprobadores") or []
    if approvers and actor not in approvers:
        problems.append(f"`{actor or '?'}` no está en la lista de aprobadores")
    return problems


def evaluate_code_scanning(alerts, policy):
    cfg = policy.get("code_scanning") or {}
    id_regex = policy.get("formato_id_excepcion", r"EXC-\d{4}-\d{3}")
    rows = []
    for a in alerts:
        if a.get("state") != "dismissed":
            continue
        rule = a.get("rule") or {}
        severity = rule.get("security_severity_level") or rule.get("severity") or ""
        reason, comment, actor = a.get("dismissed_reason") or "", a.get("dismissed_comment") or "", login(a.get("dismissed_by"))
        approved_by = login(a.get("dismissal_approved_by"))
        problems = _common_checks(reason, comment, actor, cfg, "motivos_permitidos", id_regex)
        if cfg.get("requiere_aprobacion_delegada") and severity in (cfg.get("severidades_con_aprobacion") or []) and not approved_by:
            problems.append(f"severidad `{severity}` sin aprobación delegada (`dismissal_approved_by`)")
        loc = ((a.get("most_recent_instance") or {}).get("location") or {})
        rows.append({
            "tipo": "code scanning", "alerta": a.get("number"), "url": a.get("html_url", ""),
            "hallazgo": rule.get("id", ""), "severidad": severity,
            "ubicacion": f"{loc.get('path', '')}:{loc.get('start_line', '')}",
            "motivo": reason, "justificacion": comment, "descartado_por": actor,
            "fecha": a.get("dismissed_at") or "", "aprobado_por": approved_by,
            "cumple": not problems, "problemas": "; ".join(problems),
        })
    return rows


def evaluate_secret_scanning(alerts, policy, now):
    cfg = policy.get("secret_scanning") or {}
    id_regex = policy.get("formato_id_excepcion", r"EXC-\d{4}-\d{3}")
    max_days = int(cfg.get("dias_maximos_abierta_tras_bypass", 7))
    rows = []
    for a in alerts:
        state = a.get("state")
        bypassed = bool(a.get("push_protection_bypassed"))
        if state == "resolved":
            reason, comment, actor = a.get("resolution") or "", a.get("resolution_comment") or "", login(a.get("resolved_by"))
            # "revoked" = el secreto se rotó: es una remediación, no una excepción.
            problems = [] if reason == "revoked" else \
                _common_checks(reason, comment, actor, cfg, "resoluciones_permitidas", id_regex)
            fecha = a.get("resolved_at") or ""
        elif state == "open" and bypassed:
            # Bypass de push protection: la alerta queda abierta y debe resolverse dentro del plazo.
            reason, comment, actor = "bypass push protection", a.get("push_protection_bypass_request_comment") or "", login(a.get("push_protection_bypassed_by"))
            fecha = a.get("push_protection_bypassed_at") or ""
            days = (now - parse_ts(fecha)).days if fecha else 0
            problems = [f"abierta {days} días tras el bypass (máximo {max_days})"] if days > max_days else []
        else:
            continue
        rows.append({
            "tipo": "secret scanning", "alerta": a.get("number"), "url": a.get("html_url", ""),
            "hallazgo": a.get("secret_type_display_name") or a.get("secret_type", ""), "severidad": "—",
            "ubicacion": "", "motivo": reason, "justificacion": comment, "descartado_por": actor, "fecha": fecha,
            "aprobado_por": login(a.get("push_protection_bypass_request_reviewer")) if bypassed else "",
            "cumple": not problems, "problemas": "; ".join(problems),
        })
    return rows


# ------------------------------------------------------------------------------- API

def fetch_all(path, token):
    url, items = f"{API}{path}", []
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "Authorization": f"Bearer {token}"}
    while url:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as resp:
                items += json.load(resp)
                m = re.search(r'<([^>]+)>;\s*rel="next"', resp.headers.get("Link", ""))
                url = m.group(1) if m else None
        except urllib.error.HTTPError as err:
            return err.code, items
    return 200, items


def md(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def main():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    audit_token = os.environ.get("SECURITY_AUDIT_TOKEN", "")
    policy = yaml.safe_load(Path(os.environ.get("POLICY_FILE", ".github/security/politica-descartes.yml")).read_text(encoding="utf-8"))
    now = datetime.datetime.combine(
        datetime.date.fromisoformat(os.environ["GATE_TODAY"]), datetime.time(), datetime.timezone.utc
    ) if os.environ.get("GATE_TODAY") else datetime.datetime.now(datetime.timezone.utc)

    notes, rows = [], []
    status, cs_alerts = fetch_all(f"/repos/{repo}/code-scanning/alerts?state=dismissed&per_page=100", token)
    if status == 200:
        rows += evaluate_code_scanning(cs_alerts, policy)
    else:
        notes.append(f"⚠️ Code scanning no disponible ({status}).")

    if audit_token:
        status, ss_alerts = fetch_all(f"/repos/{repo}/secret-scanning/alerts?per_page=100", audit_token)
        if status == 200:
            rows += evaluate_secret_scanning(ss_alerts, policy, now)
        else:
            notes.append(f"⚠️ Secret scanning no disponible ({status}): revisar que esté habilitado y el permiso del token.")
    else:
        notes.append("⚠️ Secret scanning omitido: falta el secreto `SECURITY_AUDIT_TOKEN` "
                     "(GITHUB_TOKEN no puede leer alertas de secret scanning).")

    csv_path = os.environ.get("AUDIT_CSV", "registro-excepciones.csv")
    fields = ["tipo", "alerta", "hallazgo", "severidad", "ubicacion", "motivo", "justificacion",
              "descartado_por", "fecha", "aprobado_por", "cumple", "problemas", "url"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    bad = [r for r in rows if not r["cumple"]]
    out = ["## 🧾 Auditoría de excepciones (code scanning y secret scanning)", "",
           f"- **Repositorio:** `{repo}`",
           f"- **Excepciones registradas:** **{len(rows)}** — cumplen la política: **{len(rows) - len(bad)}**, "
           f"no cumplen: **{len(bad)}**.",
           f"- **Registro de trazabilidad:** artifact `{Path(csv_path).name}`."]
    out += [f"- {n}" for n in notes]
    out.append("")
    if rows:
        out += ["| Tipo | Alerta | Hallazgo | Severidad | Motivo | Justificación | Por | Fecha | Aprobado por | Cumple |",
                "|---|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            mark = "✅" if r["cumple"] else f"❌ {md(r['problemas'])}"
            out.append(f"| {r['tipo']} | [#{r['alerta']}]({r['url']}) | `{md(r['hallazgo'])}` | {r['severidad']} | "
                       f"{md(r['motivo'])} | {md(r['justificacion'])[:120] or '—'} | {r['descartado_por'] or '—'} | "
                       f"{r['fecha'][:10]} | {r['aprobado_por'] or '—'} | {mark} |")
        out.append("")
    else:
        out.append("No hay alertas descartadas ni resueltas para auditar.")
    out.append("**Resultado: ❌ Hay excepciones que no cumplen la política.**" if bad
               else "**Resultado: ✅ Todas las excepciones cumplen la política.**")

    text = "\n".join(out)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    for r in bad:
        print(f"::error title=Excepción {r['tipo']} #{r['alerta']}::{r['problemas']}")
    if bad:
        sys.exit(1)


if __name__ == "__main__":
    main()
