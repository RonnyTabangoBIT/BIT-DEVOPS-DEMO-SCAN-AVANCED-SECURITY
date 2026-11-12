"""Gate de umbrales de vulnerabilidades para dependencias pip (demo/dependabot-severidad-minima).

Lee los manifiestos (requirements*.txt y Pipfile) de un directorio, consulta la GitHub Advisory
Database (la misma fuente que usa Dependabot) y aplica, en este orden:

  1. EXCEPCIONES (archivo EXCEPTIONS_FILE): vulnerabilidades aceptadas formalmente, por GHSA,
     por paquete, por rango de versiones y/o por severidad, con fecha de vencimiento.
     Las vigentes no cuentan; las vencidas dejan de aplicarse solas.
  2. REGLAS POR PAQUETE: umbral propio para un paquete y rango de versiones
     (p. ej. requests >=2.31.0 permite 4 medias, <2.31.0 solo 2). Reemplazan al umbral
     global para las severidades que definen.
  3. UMBRAL GLOBAL (MAX_*): para el resto de vulnerabilidades.

Falla si se supera algún umbral (global o de regla) o si el archivo de excepciones es inválido.

Variables de entorno:
  MANIFEST_DIRECTORY  directorio a escanear (recursivo)   por defecto: demo/dependabot-severidad-minima
  EXCEPTIONS_FILE     archivo de excepciones/reglas         por defecto: .github/security/excepciones.yml
  MAX_CRITICAL        críticas permitidas                  por defecto: 0
  MAX_HIGH            altas permitidas                     por defecto: 0
  MAX_MEDIUM          medias permitidas                    por defecto: sin límite
  MAX_LOW             bajas permitidas                     por defecto: sin límite
                      (vacío o -1 = sin límite)
  GATE_TODAY          fecha de evaluación YYYY-MM-DD (opcional, para pruebas de vencimiento)
  GITHUB_TOKEN        token para la API (opcional)
  GITHUB_STEP_SUMMARY archivo de resumen de Actions (si no existe, se imprime en stdout)
"""
import datetime
import json
import os
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
import yaml

RANK = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
ORDER = ["critical", "high", "medium", "low"]
API = "https://api.github.com/advisories"


def parse_requirements(path):
    deps = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;]+)", line)
        if m:
            deps.append((m.group(1), m.group(2), lineno))
    return deps


def parse_pipfile(path):
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    lines = text.splitlines()
    deps = []
    for section in ("packages", "dev-packages"):
        for name, spec in data.get(section, {}).items():
            spec = spec.get("version", "") if isinstance(spec, dict) else spec
            m = re.match(r"^==\s*(\S+)$", str(spec).strip())
            if not m:
                continue
            lineno = next((i for i, l in enumerate(lines, 1) if re.match(rf'^\s*"?{re.escape(name)}"?\s*=', l)), 1)
            deps.append((name, m.group(1), lineno))
    return deps


def find_dependencies(directory):
    found = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and re.fullmatch(r"requirements.*\.txt", path.name):
            found += [(path, *d) for d in parse_requirements(path)]
        elif path.is_file() and path.name == "Pipfile":
            found += [(path, *d) for d in parse_pipfile(path)]
    return found


def fetch_advisories(package, token):
    """Todas las advisories revisadas de pip para el paquete (el filtro `affects` no distingue
    mayúsculas por nombre, pero sí con `paquete@versión`, por eso se evalúa la versión localmente)."""
    url = f"{API}?ecosystem=pip&affects={package}&per_page=100"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    results = []
    while url:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as resp:
            results += json.load(resp)
            m = re.search(r'<([^>]+)>;\s*rel="next"', resp.headers.get("Link", ""))
            url = m.group(1) if m else None
    return results


def in_range(version, vulnerable_range):
    spec = ",".join(re.sub(r"^=\s*", "==", p.strip()) for p in vulnerable_range.split(","))
    try:
        return Version(version) in SpecifierSet(spec, prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return False


def matching_advisories(name, version, advisories):
    target = canonicalize_name(name)
    for adv in advisories:
        if adv.get("withdrawn_at"):
            continue
        for vuln in adv.get("vulnerabilities") or []:
            pkg = vuln.get("package") or {}
            if (pkg.get("ecosystem") == "pip" and canonicalize_name(pkg.get("name", "")) == target
                    and in_range(version, vuln.get("vulnerable_version_range") or "")):
                yield adv
                break


def md(text):
    return (text or "").replace("|", "\\|").replace("\n", " ")




LABELS = {"critical": "Críticas", "high": "Altas", "medium": "Medias", "low": "Bajas"}
DEFAULT_LIMITS = {"critical": "0", "high": "0", "medium": "", "low": ""}
DEFAULT_POLICY = {"max_dias_vigencia": 90, "aviso_dias_antes": 15, "permitir_excepcion_critical": False}


def read_limits():
    """Umbral global permitido por severidad; None = sin límite."""
    limits = {}
    for sev in ORDER:
        raw = os.environ.get(f"MAX_{sev.upper()}", DEFAULT_LIMITS[sev]).strip()
        try:
            value = int(raw) if raw else -1
        except ValueError:
            sys.exit(f"MAX_{sev.upper()} inválido: {raw!r} (use un entero, vacío o -1 = sin límite)")
        limits[sev] = None if value < 0 else value
    return limits


# --------------------------------------------------------------------------- política de excepciones

def to_date(value):
    if isinstance(value, datetime.date):
        return value
    return datetime.date.fromisoformat(str(value))


def to_spec(value):
    return SpecifierSet(str(value).replace(" ", ""), prereleases=True) if value else None


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
        problems = []
        for field in ("id", "justificacion", "aprobado_por", "vence"):
            if not raw.get(field):
                problems.append(f"falta `{field}`")
        if not raw.get("paquete") and not raw.get("ghsa"):
            problems.append("debe indicar `paquete` y/o `ghsa`")
        if raw.get("id") in seen:
            problems.append("`id` duplicado")
        seen.add(raw.get("id"))
        sevs = [str(s).lower() for s in raw.get("severidades") or []]
        if any(s not in ORDER for s in sevs):
            problems.append(f"`severidades` inválidas: {sevs}")
        if "critical" in sevs and not policy["permitir_excepcion_critical"]:
            problems.append("la política no permite exceptuar vulnerabilidades `critical`")
        try:
            spec = to_spec(raw.get("versiones"))
        except InvalidSpecifier:
            problems.append(f"`versiones` inválido: {raw.get('versiones')!r}")
            spec = None
        try:
            expires = to_date(raw["vence"]) if raw.get("vence") else None
        except ValueError:
            problems.append(f"`vence` inválido: {raw.get('vence')!r} (use AAAA-MM-DD)")
            expires = None
        if expires and expires > max_date:
            problems.append(f"`vence` {expires} supera el máximo de {policy['max_dias_vigencia']} días ({max_date})")
        if problems:
            errors.append(f"Excepción {ref}: " + "; ".join(problems))
            continue
        exceptions.append({
            "id": raw["id"], "ghsa": raw.get("ghsa"), "paquete": raw.get("paquete"),
            "spec": spec, "versiones": raw.get("versiones") or "", "severidades": sevs,
            "vence": expires, "aprobado_por": raw["aprobado_por"], "solicitado_por": raw.get("solicitado_por", ""),
            "justificacion": raw["justificacion"], "cubre": 0,
        })

    for i, raw in enumerate(data.get("reglas_por_paquete") or [], 1):
        ref = raw.get("id") or f"reglas_por_paquete[{i}]"
        problems = []
        for field in ("id", "paquete", "versiones", "max", "justificacion"):
            if not raw.get(field) and raw.get(field) != 0:
                problems.append(f"falta `{field}`")
        if raw.get("id") in seen:
            problems.append("`id` duplicado")
        seen.add(raw.get("id"))
        try:
            spec = to_spec(raw.get("versiones"))
        except InvalidSpecifier:
            problems.append(f"`versiones` inválido: {raw.get('versiones')!r}")
            spec = None
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
        rules.append({"id": raw["id"], "paquete": raw["paquete"], "spec": spec,
                      "versiones": raw["versiones"], "max": limits, "justificacion": raw["justificacion"]})
    return policy, exceptions, rules, errors


def version_in(spec, version):
    if spec is None:
        return True
    try:
        return Version(version) in spec
    except InvalidVersion:
        return False


def find_exception(finding, exceptions, today, policy):
    for exc in exceptions:
        if exc["vence"] < today:
            continue
        if exc["ghsa"] and exc["ghsa"].upper() != finding["ghsa"].upper():
            continue
        if exc["paquete"] and canonicalize_name(exc["paquete"]) != canonicalize_name(finding["package"]):
            continue
        if not version_in(exc["spec"], finding["version"]):
            continue
        if exc["severidades"] and finding["severity"] not in exc["severidades"]:
            continue
        if finding["severity"] == "critical" and not policy["permitir_excepcion_critical"]:
            continue
        return exc
    return None


def find_rule(finding, rules):
    for rule in rules:
        if (canonicalize_name(rule["paquete"]) == canonicalize_name(finding["package"])
                and version_in(rule["spec"], finding["version"])
                and finding["severity"] in rule["max"]):
            return rule
    return None


# --------------------------------------------------------------------------- main

def main():
    directory = Path(os.environ.get("MANIFEST_DIRECTORY", "demo/dependabot-severidad-minima"))
    exceptions_file = Path(os.environ.get("EXCEPTIONS_FILE", ".github/security/excepciones.yml"))
    today = to_date(os.environ.get("GATE_TODAY") or datetime.date.today())
    token = os.environ.get("GITHUB_TOKEN", "")
    limits = read_limits()
    policy, exceptions, rules, config_errors = load_policy(exceptions_file, today)

    deps = find_dependencies(directory)
    cache, findings = {}, []
    for path, name, version, lineno in deps:
        key = canonicalize_name(name)
        if key not in cache:
            cache[key] = fetch_advisories(key, token)
        for adv in matching_advisories(name, version, cache[key]):
            severity = "medium" if adv["severity"] == "moderate" else adv["severity"]
            findings.append({
                "manifest": path.as_posix(), "line": lineno, "package": name, "version": version,
                "severity": severity, "ghsa": adv["ghsa_id"], "url": adv["html_url"],
                "summary": adv.get("summary", ""),
            })
    findings.sort(key=lambda f: (-RANK.get(f["severity"], 0), f["manifest"], f["package"]))

    # Clasificación: excepción vigente > regla por paquete > umbral global.
    for f in findings:
        exc = find_exception(f, exceptions, today, policy)
        rule = None if exc else find_rule(f, rules)
        f["exception"], f["rule"] = exc, rule
        if exc:
            exc["cubre"] += 1

    global_counts = {sev: sum(f["severity"] == sev and not f["exception"] and not f["rule"] for f in findings)
                     for sev in ORDER}
    global_exceeded = {sev for sev in ORDER if limits[sev] is not None and global_counts[sev] > limits[sev]}

    rule_rows, rule_exceeded = [], set()
    for rule in rules:
        installed = sorted({f"{f['package']}=={f['version']}" for f in findings if f["rule"] is rule})
        for sev, allowed in rule["max"].items():
            count = sum(f["rule"] is rule and f["severity"] == sev for f in findings)
            if count > allowed:
                rule_exceeded.add((rule["id"], sev))
            rule_rows.append((rule, installed, sev, count, allowed))

    def blocks(f):
        if f["exception"]:
            return False
        if f["rule"]:
            return (f["rule"]["id"], f["severity"]) in rule_exceeded
        return f["severity"] in global_exceeded

    failed = bool(global_exceeded or rule_exceeded or config_errors)
    n_exc = sum(1 for f in findings if f["exception"])
    n_rule = sum(1 for f in findings if f["rule"])

    def fmt_limit(value):
        return "sin límite" if value is None else str(value)

    out = [
        "## 🛡️ Dependabot: umbral de vulnerabilidades por severidad",
        "",
        f"- **Directorio analizado:** `{directory.as_posix()}/` ({len(deps)} dependencias fijadas).",
        f"- **Archivo de excepciones:** `{exceptions_file.as_posix()}` "
        f"({len(exceptions)} excepciones, {len(rules)} reglas por paquete){'' if exceptions_file.is_file() else ' — no existe'}.",
        f"- **Total de vulnerabilidades encontradas:** **{len(findings)}** — exceptuadas: **{n_exc}**, "
        f"evaluadas por regla de paquete: **{n_rule}**, evaluadas por umbral global: **{len(findings) - n_exc - n_rule}**.",
        "",
    ]
    if config_errors:
        out += ["### ❌ Errores en el archivo de excepciones", ""] + [f"- {e}" for e in config_errors] + [""]

    out += [
        "### Umbral global",
        "",
        "| Severidad | Encontradas | Exceptuadas | Por regla de paquete | Cuentan | Permitidas | Exceso | Estado |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for sev in ORDER:
        found = sum(f["severity"] == sev for f in findings)
        excepted = sum(f["severity"] == sev and bool(f["exception"]) for f in findings)
        by_rule = sum(f["severity"] == sev and bool(f["rule"]) for f in findings)
        over = 0 if limits[sev] is None else max(0, global_counts[sev] - limits[sev])
        status = "❌ Supera el umbral" if sev in global_exceeded else "✅ Dentro del umbral"
        out.append(f"| {LABELS[sev]} ({sev}) | {found} | {excepted} | {by_rule} | {global_counts[sev]} | "
                   f"{fmt_limit(limits[sev])} | {over} | {status} |")
    out.append(f"| **Total** | **{len(findings)}** | **{n_exc}** | **{n_rule}** | **{sum(global_counts.values())}** "
               f"| | | {'❌' if global_exceeded else '✅'} |")
    out.append("")

    if rules:
        out += ["### Reglas por paquete y versión", "",
                "| Regla | Paquete | Versiones de la regla | Instalada | Severidad | Encontradas | Permitidas | Estado |",
                "|---|---|---|---|---|---:|---:|---|"]
        for rule, installed, sev, count, allowed in rule_rows:
            status = "❌ Supera el umbral" if (rule["id"], sev) in rule_exceeded else "✅ Dentro del umbral"
            out.append(f"| `{rule['id']}` | {rule['paquete']} | `{rule['versiones']}` | "
                       f"{', '.join(installed) or '— (no aplica)'} | {sev} | {count} | {allowed} | {status} |")
        out.append("")

    warnings = []
    if exceptions:
        out += ["### Control de excepciones", "",
                "| ID | Alcance | Vulnerabilidades cubiertas | Vence | Estado | Aprobado por | Justificación |",
                "|---|---|---:|---|---|---|---|"]
        for exc in exceptions:
            scope = " · ".join(filter(None, [
                exc["ghsa"] and f"`{exc['ghsa']}`", exc["paquete"],
                exc["versiones"] and f"`{exc['versiones']}`",
                exc["severidades"] and "/".join(exc["severidades"])]))
            days = (exc["vence"] - today).days
            if days < 0:
                state = "⛔ Vencida (no se aplica)"
                warnings.append(f"Excepción {exc['id']} vencida el {exc['vence']}: ya no se aplica.")
            elif exc["cubre"] == 0:
                state = "⚠️ Vigente, sin coincidencias"
                warnings.append(f"Excepción {exc['id']} vigente pero no cubre ninguna vulnerabilidad: revisar si sigue siendo necesaria.")
            elif days <= int(policy["aviso_dias_antes"]):
                state = f"⏳ Vence en {days} día(s)"
                warnings.append(f"Excepción {exc['id']} vence en {days} día(s) ({exc['vence']}).")
            else:
                state = f"✅ Vigente ({days} días)"
            out.append(f"| `{exc['id']}` | {scope} | {exc['cubre']} | {exc['vence']} | {state} | "
                       f"{md(str(exc['aprobado_por']))} | {md(exc['justificacion'])} |")
        out.append("")

    if findings:
        out += ["### Detalle", "",
                "| Manifiesto | Paquete | Severidad | Tratamiento | Bloquea | Advisory | Descripción |",
                "|---|---|---|---|---|---|---|"]
        for f in findings:
            if f["exception"]:
                treatment = f"Exceptuada (`{f['exception']['id']}`)"
            elif f["rule"]:
                treatment = f"Regla `{f['rule']['id']}`"
            else:
                treatment = "Umbral global"
            out.append(f"| `{f['manifest']}` | {f['package']}=={f['version']} | {f['severity']} | {treatment} | "
                       f"{'❌' if blocks(f) else '➖'} | [{f['ghsa']}]({f['url']}) | {md(f['summary'])} |")
        out.append("")

    if failed:
        reasons = [f"{LABELS[s].lower()} {global_counts[s]} de {limits[s]} permitidas (global)" for s in ORDER if s in global_exceeded]
        reasons += [f"regla {rid} ({sev})" for rid, sev in sorted(rule_exceeded)]
        if config_errors:
            reasons.append("archivo de excepciones inválido")
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
        print(f"::warning file={exceptions_file.as_posix()},title=Control de excepciones::{w}")
    for e in config_errors:
        print(f"::error file={exceptions_file.as_posix()},title=Excepciones inválidas::{e}")
    if failed:
        for f in findings:
            if blocks(f):
                print(f"::error file={f['manifest']},line={f['line']},title={f['severity'].upper()} "
                      f"{f['ghsa']}::{f['package']}=={f['version']}: {f['summary']}")
        for sev in ORDER:
            if sev in global_exceeded:
                print(f"::error::Vulnerabilidades {LABELS[sev].lower()}: {global_counts[sev]} cuentan para el umbral global, "
                      f"{limits[sev]} permitidas.")
        for rule, _, sev, count, allowed in rule_rows:
            if (rule["id"], sev) in rule_exceeded:
                print(f"::error::Regla {rule['id']} ({rule['paquete']} {rule['versiones']}): {count} {sev} encontradas, "
                      f"{allowed} permitidas.")
        sys.exit(1)


if __name__ == "__main__":
    main()
