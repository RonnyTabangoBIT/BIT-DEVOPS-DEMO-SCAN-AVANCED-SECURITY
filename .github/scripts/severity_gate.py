"""Gate de umbrales de vulnerabilidades para dependencias pip (demo/dependabot-severidad-minima).

Lee los manifiestos (requirements*.txt y Pipfile) de un directorio, consulta la GitHub Advisory
Database (la misma fuente que usa Dependabot) y falla cuando, para alguna severidad, la cantidad de
vulnerabilidades encontradas supera la cantidad permitida para esa severidad.

A diferencia de la API de alertas de Dependabot, funciona en cualquier rama/PR y solo necesita
GITHUB_TOKEN (opcional, para evitar el límite de peticiones anónimas).

Variables de entorno:
  MANIFEST_DIRECTORY  directorio a escanear (recursivo)   por defecto: demo/dependabot-severidad-minima
  MAX_CRITICAL        críticas permitidas                  por defecto: 0
  MAX_HIGH            altas permitidas                     por defecto: 0
  MAX_MEDIUM          medias permitidas                    por defecto: sin límite
  MAX_LOW             bajas permitidas                     por defecto: sin límite
                      (vacío o -1 = sin límite)
  GITHUB_TOKEN        token para la API (opcional)
  GITHUB_STEP_SUMMARY archivo de resumen de Actions (si no existe, se imprime en stdout)
"""
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


def read_limits():
    """Umbral permitido por severidad; None = sin límite."""
    limits = {}
    for sev in ORDER:
        raw = os.environ.get(f"MAX_{sev.upper()}", DEFAULT_LIMITS[sev]).strip()
        try:
            value = int(raw) if raw else -1
        except ValueError:
            sys.exit(f"MAX_{sev.upper()} inválido: {raw!r} (use un entero, vacío o -1 = sin límite)")
        limits[sev] = None if value < 0 else value
    return limits


def main():
    directory = Path(os.environ.get("MANIFEST_DIRECTORY", "demo/dependabot-severidad-minima"))
    token = os.environ.get("GITHUB_TOKEN", "")
    limits = read_limits()

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
    counts = {sev: sum(f["severity"] == sev for f in findings) for sev in ORDER}
    exceeded = [sev for sev in ORDER if limits[sev] is not None and counts[sev] > limits[sev]]

    def fmt_limit(sev):
        return "sin límite" if limits[sev] is None else str(limits[sev])

    out = [
        "## 🛡️ Dependabot: umbral de vulnerabilidades por severidad",
        "",
        f"- **Directorio analizado:** `{directory.as_posix()}/` ({len(deps)} dependencias fijadas).",
        f"- **Total de vulnerabilidades encontradas:** **{len(findings)}**.",
        f"- **Severidades que superan su umbral:** "
        f"{', '.join(f'**{LABELS[s]}**' for s in exceeded) if exceeded else 'ninguna'}.",
        "",
        "| Severidad | Encontradas | Permitidas | Exceso | Estado |",
        "|---|---:|---:|---:|---|",
    ]
    for sev in ORDER:
        over = 0 if limits[sev] is None else max(0, counts[sev] - limits[sev])
        status = "❌ Supera el umbral" if sev in exceeded else "✅ Dentro del umbral"
        out.append(f"| {LABELS[sev]} ({sev}) | {counts[sev]} | {fmt_limit(sev)} | {over} | {status} |")
    out.append(f"| **Total** | **{len(findings)}** | | | {'❌' if exceeded else '✅'} |")
    out.append("")
    if findings:
        out += ["| Manifiesto | Paquete | Severidad | Supera umbral | Advisory | Descripción |",
                "|---|---|---|---|---|---|"]
        for f in findings:
            out.append(f"| `{f['manifest']}` | {f['package']}=={f['version']} | {f['severity']} | "
                       f"{'❌' if f['severity'] in exceeded else '➖'} | [{f['ghsa']}]({f['url']}) | {md(f['summary'])} |")
        out.append("")
    if exceeded:
        detail = ", ".join(f"{LABELS[s].lower()} {counts[s]} de {limits[s]} permitidas" for s in exceeded)
        out.append(f"**Resultado: ❌ Se supera el umbral de vulnerabilidades permitidas ({detail}).**")
    else:
        out.append("**Resultado: ✅ Todas las severidades están dentro de su umbral.**")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    else:
        print("\n".join(out))

    if exceeded:
        # Anotaciones en el archivo/línea del manifiesto (visibles en el PR y en el run).
        for f in findings:
            if f["severity"] in exceeded:
                print(f"::error file={f['manifest']},line={f['line']},title={f['severity'].upper()} "
                      f"{f['ghsa']}::{f['package']}=={f['version']}: {f['summary']}")
        for sev in exceeded:
            print(f"::error::Vulnerabilidades {LABELS[sev].lower()}: {counts[sev]} encontradas, "
                  f"{limits[sev]} permitidas.")
        sys.exit(1)


if __name__ == "__main__":
    main()
