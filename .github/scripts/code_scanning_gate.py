"""Gate de umbrales para hallazgos de code scanning (CodeQL), con control de excepciones.

Funciona igual que el gate de dependencias (severity_gate.py), pero sobre los resultados SARIF de CodeQL:

  1. EXCEPCIONES (archivo EXCEPTIONS_FILE): hallazgos aceptados formalmente por REGLA de CodeQL y RUTA,
     opcionalmente por severidad, con fecha de vencimiento. Las vigentes no cuentan; las vencidas dejan de aplicarse.
  2. REGLAS POR RUTA: umbral propio para una ruta (p. ej. demo/** permite N altas). Reemplazan al umbral global
     para las severidades que definen.
  3. UMBRAL GLOBAL (MAX_*): para el resto de hallazgos.

Falla si se supera algún umbral (global o de regla) o si el archivo de excepciones es inválido.
Lee los SARIF del job `codeql`, así que funciona igual en push y en pull request, sin consultar la API.

Variables de entorno:
  SARIF_DIR           carpeta con los .sarif de CodeQL              por defecto: sarif
  EXCEPTIONS_FILE     archivo de excepciones de código              por defecto: .github/security/excepciones-codigo.yml
  MAX_CRITICAL        críticas permitidas                           por defecto: 0
  MAX_HIGH            altas permitidas                              por defecto: 0
  MAX_MEDIUM          medias permitidas                             por defecto: sin límite
  MAX_LOW             bajas permitidas                              por defecto: sin límite
                      (vacío o -1 = sin límite)
  GATE_TODAY          fecha de evaluación AAAA-MM-DD (opcional, para pruebas de vencimiento)
  GITHUB_STEP_SUMMARY archivo de resumen de Actions (si no existe, se imprime en stdout)
"""
import datetime
import fnmatch
import json
import os
import sys
from pathlib import Path

import yaml

ORDER = ["critical", "high", "medium", "low"]
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LABELS = {"critical": "Críticas", "high": "Altas", "medium": "Medias", "low": "Bajas"}
DEFAULT_LIMITS = {"critical": "0", "high": "0", "medium": "", "low": ""}
DEFAULT_POLICY = {"max_dias_vigencia": 90, "aviso_dias_antes": 15, "permitir_excepcion_critical": False}


# ------------------------------------------------------------------------------- SARIF

def severity_from_score(score):
    """Misma escala que GitHub para `security-severity` (CVSS)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else None


def load_findings(sarif_dir):
    """Devuelve (hallazgos de seguridad, cantidad de resultados sin severidad de seguridad, archivos leídos)."""
    findings, skipped, files = [], 0, sorted(Path(sarif_dir).glob("**/*.sarif"))
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            tool = run.get("tool") or {}
            components = [tool.get("driver") or {}] + list(tool.get("extensions") or [])
            rules = {}
            for comp in components:
                for rule in comp.get("rules") or []:
                    rules[rule.get("id")] = rule
            for res in run.get("results") or []:
                if res.get("suppressions"):
                    continue
                rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id", "")
                rule = rules.get(rule_id) or {}
                props = rule.get("properties") or {}
                try:
                    severity = severity_from_score(float(props.get("security-severity", 0)))
                except (TypeError, ValueError):
                    severity = None
                if not severity:
                    skipped += 1
                    continue
                loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                findings.append({
                    "rule": rule_id,
                    "path": (loc.get("artifactLocation") or {}).get("uri", ""),
                    "line": (loc.get("region") or {}).get("startLine", 1),
                    "severity": severity,
                    "score": props.get("security-severity"),
                    "message": ((res.get("message") or {}).get("text") or "").split("\n")[0],
                })
    return findings, skipped, files


# ------------------------------------------------------------------------------- política de excepciones

def read_limits():
    limits = {}
    for sev in ORDER:
        raw = os.environ.get(f"MAX_{sev.upper()}", DEFAULT_LIMITS[sev]).strip()
        try:
            value = int(raw) if raw else -1
        except ValueError:
            sys.exit(f"MAX_{sev.upper()} inválido: {raw!r} (use un entero, vacío o -1 = sin límite)")
        limits[sev] = None if value < 0 else value
    return limits


def to_date(value):
    return value if isinstance(value, datetime.date) else datetime.date.fromisoformat(str(value))


def load_policy(path, today):
    """Lee y valida el archivo. Devuelve (politica, excepciones, reglas, errores)."""
    policy, exceptions, rules, errors = dict(DEFAULT_POLICY), [], [], []
    if not path.is_file():
        return policy, exceptions, rules, errors
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return policy, exceptions, rules, [f"YAML inválido: {exc}"]

    policy.update(data.get("politica") or {})
    max_date = today + datetime.timedelta(days=int(policy["max_dias_vigencia"]))
    seen = set()

    for i, raw in enumerate(data.get("excepciones") or [], 1):
        ref = raw.get("id") or f"excepciones[{i}]"
        problems = [f"falta `{f}`" for f in ("id", "regla", "ruta", "justificacion", "aprobado_por", "vence") if not raw.get(f)]
        if raw.get("id") in seen:
            problems.append("`id` duplicado")
        seen.add(raw.get("id"))
        if raw.get("ruta") in ("*", "**", "**/*"):
            problems.append("`ruta` demasiado amplia: una excepción no puede cubrir todo el repositorio")
        sevs = [str(s).lower() for s in raw.get("severidades") or []]
        if any(s not in ORDER for s in sevs):
            problems.append(f"`severidades` inválidas: {sevs}")
        if "critical" in sevs and not policy["permitir_excepcion_critical"]:
            problems.append("la política no permite exceptuar hallazgos `critical`")
        expires = None
        if raw.get("vence"):
            try:
                expires = to_date(raw["vence"])
            except ValueError:
                problems.append(f"`vence` inválido: {raw.get('vence')!r} (use AAAA-MM-DD)")
        if expires and expires > max_date:
            problems.append(f"`vence` {expires} supera el máximo de {policy['max_dias_vigencia']} días ({max_date})")
        if problems:
            errors.append(f"Excepción {ref}: " + "; ".join(problems))
            continue
        exceptions.append({"id": raw["id"], "regla": raw["regla"], "ruta": raw["ruta"], "severidades": sevs,
                           "vence": expires, "aprobado_por": raw["aprobado_por"],
                           "solicitado_por": raw.get("solicitado_por", ""), "justificacion": raw["justificacion"],
                           "cubre": 0})

    for i, raw in enumerate(data.get("reglas_por_ruta") or [], 1):
        ref = raw.get("id") or f"reglas_por_ruta[{i}]"
        problems = [f"falta `{f}`" for f in ("id", "ruta", "max", "justificacion") if not raw.get(f)]
        if raw.get("id") in seen:
            problems.append("`id` duplicado")
        seen.add(raw.get("id"))
        limits = {}
        for sev, value in (raw.get("max") or {}).items():
            sev = str(sev).lower()
            if sev not in ORDER or not isinstance(value, int) or value < 0:
                problems.append(f"`max.{sev}` inválido: {value!r} (severidad válida y entero >= 0)")
            else:
                limits[sev] = value
        if problems:
            errors.append(f"Regla {ref}: " + "; ".join(problems))
            continue
        rules.append({"id": raw["id"], "ruta": raw["ruta"], "regla": raw.get("regla") or "*",
                      "max": limits, "justificacion": raw["justificacion"]})
    return policy, exceptions, rules, errors


def matches(pattern, value):
    return fnmatch.fnmatchcase(value, pattern)


def find_exception(finding, exceptions, today, policy):
    for exc in exceptions:
        if exc["vence"] < today:
            continue
        if not matches(exc["regla"], finding["rule"]) or not matches(exc["ruta"], finding["path"]):
            continue
        if exc["severidades"] and finding["severity"] not in exc["severidades"]:
            continue
        if finding["severity"] == "critical" and not policy["permitir_excepcion_critical"]:
            continue
        return exc
    return None


def find_rule(finding, rules):
    for rule in rules:
        if (matches(rule["ruta"], finding["path"]) and matches(rule["regla"], finding["rule"])
                and finding["severity"] in rule["max"]):
            return rule
    return None


def md(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


# ------------------------------------------------------------------------------- main

def main():
    sarif_dir = Path(os.environ.get("SARIF_DIR", "sarif"))
    exceptions_file = Path(os.environ.get("EXCEPTIONS_FILE", ".github/security/excepciones-codigo.yml"))
    today = to_date(os.environ.get("GATE_TODAY") or datetime.date.today())
    limits = read_limits()
    policy, exceptions, rules, config_errors = load_policy(exceptions_file, today)
    findings, skipped, files = load_findings(sarif_dir)
    if not files:
        config_errors.append(f"No se encontraron archivos SARIF en `{sarif_dir}`: el análisis de CodeQL no generó resultados.")
    findings.sort(key=lambda f: (-RANK[f["severity"]], f["path"], f["line"]))

    for f in findings:
        exc = find_exception(f, exceptions, today, policy)
        rule = None if exc else find_rule(f, rules)
        f["exception"], f["rulecfg"] = exc, rule
        if exc:
            exc["cubre"] += 1

    global_counts = {s: sum(f["severity"] == s and not f["exception"] and not f["rulecfg"] for f in findings) for s in ORDER}
    global_exceeded = {s for s in ORDER if limits[s] is not None and global_counts[s] > limits[s]}
    rule_rows, rule_exceeded = [], set()
    for rule in rules:
        for sev, allowed in rule["max"].items():
            count = sum(f["rulecfg"] is rule and f["severity"] == sev for f in findings)
            if count > allowed:
                rule_exceeded.add((rule["id"], sev))
            rule_rows.append((rule, sev, count, allowed))

    def blocks(f):
        if f["exception"]:
            return False
        if f["rulecfg"]:
            return (f["rulecfg"]["id"], f["severity"]) in rule_exceeded
        return f["severity"] in global_exceeded

    failed = bool(global_exceeded or rule_exceeded or config_errors)
    n_exc = sum(1 for f in findings if f["exception"])
    n_rule = sum(1 for f in findings if f["rulecfg"])
    fmt = lambda v: "sin límite" if v is None else str(v)  # noqa: E731

    out = [
        "## 🛡️ Code scanning: umbral de hallazgos por severidad",
        "",
        f"- **Resultados analizados:** {len(files)} archivo(s) SARIF de CodeQL; {len(findings)} hallazgos de seguridad "
        f"({skipped} resultados sin severidad de seguridad no se evalúan).",
        f"- **Archivo de excepciones:** `{exceptions_file.as_posix()}` ({len(exceptions)} excepciones, "
        f"{len(rules)} reglas por ruta){'' if exceptions_file.is_file() else ' — no existe'}.",
        f"- **Hallazgos:** exceptuados **{n_exc}**, evaluados por regla de ruta **{n_rule}**, "
        f"evaluados por umbral global **{len(findings) - n_exc - n_rule}**.",
        "",
    ]
    if config_errors:
        out += ["### ❌ Errores", ""] + [f"- {e}" for e in config_errors] + [""]

    out += ["### Umbral global", "",
            "| Severidad | Encontrados | Exceptuados | Por regla de ruta | Cuentan | Permitidos | Exceso | Estado |",
            "|---|---:|---:|---:|---:|---:|---:|---|"]
    for sev in ORDER:
        found = sum(f["severity"] == sev for f in findings)
        exc_n = sum(f["severity"] == sev and bool(f["exception"]) for f in findings)
        rule_n = sum(f["severity"] == sev and bool(f["rulecfg"]) for f in findings)
        over = 0 if limits[sev] is None else max(0, global_counts[sev] - limits[sev])
        state = "❌ Supera el umbral" if sev in global_exceeded else "✅ Dentro del umbral"
        out.append(f"| {LABELS[sev]} ({sev}) | {found} | {exc_n} | {rule_n} | {global_counts[sev]} | "
                   f"{fmt(limits[sev])} | {over} | {state} |")
    out.append(f"| **Total** | **{len(findings)}** | **{n_exc}** | **{n_rule}** | **{sum(global_counts.values())}** "
               f"| | | {'❌' if global_exceeded else '✅'} |")
    out.append("")

    if rules:
        out += ["### Reglas por ruta", "",
                "| Regla | Ruta | Reglas de CodeQL | Severidad | Encontrados | Permitidos | Estado |",
                "|---|---|---|---|---:|---:|---|"]
        for rule, sev, count, allowed in rule_rows:
            state = "❌ Supera el umbral" if (rule["id"], sev) in rule_exceeded else "✅ Dentro del umbral"
            out.append(f"| `{rule['id']}` | `{rule['ruta']}` | `{rule['regla']}` | {sev} | {count} | {allowed} | {state} |")
        out.append("")

    warnings = []
    if exceptions:
        out += ["### Control de excepciones", "",
                "| ID | Regla de CodeQL | Ruta | Hallazgos cubiertos | Vence | Estado | Aprobado por | Justificación |",
                "|---|---|---|---:|---|---|---|---|"]
        for exc in exceptions:
            days = (exc["vence"] - today).days
            if days < 0:
                state = "⛔ Vencida (no se aplica)"
                warnings.append(f"Excepción {exc['id']} vencida el {exc['vence']}: ya no se aplica.")
            elif exc["cubre"] == 0:
                state = "⚠️ Vigente, sin coincidencias"
                warnings.append(f"Excepción {exc['id']} vigente pero no cubre ningún hallazgo: revisar si sigue siendo necesaria.")
            elif days <= int(policy["aviso_dias_antes"]):
                state = f"⏳ Vence en {days} día(s)"
                warnings.append(f"Excepción {exc['id']} vence en {days} día(s) ({exc['vence']}).")
            else:
                state = f"✅ Vigente ({days} días)"
            sevs = f" ({'/'.join(exc['severidades'])})" if exc["severidades"] else ""
            out.append(f"| `{exc['id']}` | `{exc['regla']}`{sevs} | `{exc['ruta']}` | {exc['cubre']} | {exc['vence']} | "
                       f"{state} | {md(exc['aprobado_por'])} | {md(exc['justificacion'])} |")
        out.append("")

    if findings:
        out += ["### Detalle", "",
                "| Ubicación | Regla de CodeQL | Severidad | Tratamiento | Bloquea | Descripción |",
                "|---|---|---|---|---|---|"]
        for f in findings:
            if f["exception"]:
                treatment = f"Exceptuado (`{f['exception']['id']}`)"
            elif f["rulecfg"]:
                treatment = f"Regla `{f['rulecfg']['id']}`"
            else:
                treatment = "Umbral global"
            out.append(f"| `{f['path']}:{f['line']}` | `{f['rule']}` | {f['severity']} ({f['score']}) | {treatment} | "
                       f"{'❌' if blocks(f) else '➖'} | {md(f['message'])[:150]} |")
        out.append("")

    if failed:
        reasons = [f"{LABELS[s].lower()} {global_counts[s]} de {limits[s]} permitidas (global)" for s in ORDER if s in global_exceeded]
        reasons += [f"regla {rid} ({sev})" for rid, sev in sorted(rule_exceeded)]
        if config_errors:
            reasons.append("errores de configuración")
        out.append(f"**Resultado: ❌ El gate falla ({'; '.join(reasons)}).**")
    else:
        out.append("**Resultado: ✅ Todas las severidades están dentro de su umbral.**")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    else:
        print("\n".join(out))

    for w in warnings:
        print(f"::warning file={exceptions_file.as_posix()},title=Excepciones de código::{w}")
    for e in config_errors:
        print(f"::error file={exceptions_file.as_posix()},title=Excepciones de código inválidas::{e}")
    if failed:
        for f in findings:
            if blocks(f):
                print(f"::error file={f['path']},line={f['line']},title={f['severity'].upper()} {f['rule']}::{f['message']}")
        for sev in sorted(global_exceeded, key=lambda s: -RANK[s]):
            print(f"::error::Hallazgos {LABELS[sev].lower()}: {global_counts[sev]} cuentan para el umbral global, "
                  f"{limits[sev]} permitidos.")
        for rule, sev, count, allowed in rule_rows:
            if (rule["id"], sev) in rule_exceeded:
                print(f"::error::Regla {rule['id']} ({rule['ruta']}): {count} {sev} encontrados, {allowed} permitidos.")
        sys.exit(1)


if __name__ == "__main__":
    main()
