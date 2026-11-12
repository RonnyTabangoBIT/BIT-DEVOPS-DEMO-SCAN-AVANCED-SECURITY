"""Pruebas del gate de code scanning (umbrales, reglas por ruta y control de excepciones) con SARIF simulados."""
import copy
import datetime
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import code_scanning_gate as gate  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
SECURITY = ROOT / ".github" / "security"
SARIF_DIR = SECURITY / "pruebas" / "sarif"
EXCEPTIONS = SECURITY / "excepciones-codigo.yml"
TODAY = datetime.date(2026, 11, 12)
LIMITS = {"MAX_CRITICAL": "0", "MAX_HIGH": "0", "MAX_MEDIUM": "2", "MAX_LOW": "-1"}


def run_gate(monkeypatch, capsys, sarif_dir=SARIF_DIR, exceptions=EXCEPTIONS, today="2026-11-12", **limits):
    monkeypatch.chdir(ROOT)
    for key, value in {**LIMITS, **limits}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SARIF_DIR", str(sarif_dir))
    monkeypatch.setenv("EXCEPTIONS_FILE", str(exceptions))
    monkeypatch.setenv("GATE_TODAY", today)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    try:
        gate.main()
        code = 0
    except SystemExit as exc:
        code = exc.code
    return code, capsys.readouterr().out


def sarif_with_extra(tmp_path, extra):
    """Copia los SARIF simulados y agrega resultados (rule_id, score, path, line)."""
    for src in SARIF_DIR.glob("*.sarif"):
        data = json.loads(src.read_text(encoding="utf-8"))
        if src.name == "python.sarif":
            run = data["runs"][0]
            for rule_id, score, path, line in extra:
                run["tool"]["extensions"][0]["rules"].append({"id": rule_id, "properties": {"security-severity": score}})
                run["results"].append(copy.deepcopy(run["results"][0]) | {
                    "ruleId": rule_id, "message": {"text": f"{rule_id} simulado"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}]})
        (tmp_path / src.name).write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


# ------------------------------------------------------------------------------- SARIF

@pytest.mark.parametrize("score, severity", [(9.8, "critical"), (9.0, "critical"), (8.8, "high"), (7.0, "high"),
                                             (6.1, "medium"), (4.0, "medium"), (3.9, "low"), (0, None)])
def test_severidad_segun_escala_de_github(score, severity):
    assert gate.severity_from_score(score) == severity


def test_lee_reglas_de_extensions_y_omite_resultados_sin_severidad():
    findings, skipped, files = gate.load_findings(SARIF_DIR)
    assert len(files) == 2 and len(findings) == 9 and skipped == 1
    assert {f["rule"]: f["severity"] for f in findings}["py/command-line-injection"] == "critical"


# ------------------------------------------------------------------------------- Escenarios del gate

def test_estado_actual_pasa_con_avisos(monkeypatch, capsys):
    code, out = run_gate(monkeypatch, capsys)
    assert code == 0, out
    assert "exceptuados **3**, evaluados por regla de ruta **6**, evaluados por umbral global **0**" in out
    assert "EXC-COD-2026-002 vence en 8 día(s)" in out
    assert "EXC-COD-2026-004 vencida" in out


def test_hallazgo_critico_fuera_de_demo_bloquea(monkeypatch, capsys, tmp_path):
    sarif = sarif_with_extra(tmp_path, [("py/code-injection", "9.3", ".github/scripts/nuevo.py", 10)])
    code, out = run_gate(monkeypatch, capsys, sarif_dir=sarif)
    assert code == 1
    assert "críticas 1 de 0 permitidas (global)" in out
    assert "::error file=.github/scripts/nuevo.py,line=10,title=CRITICAL py/code-injection" in out


def test_regla_por_ruta_superada_bloquea(monkeypatch, capsys, tmp_path):
    sarif = sarif_with_extra(tmp_path, [("py/code-injection", "9.3", "demo/codeql-code-scanning/app/otro.py", 5)])
    code, out = run_gate(monkeypatch, capsys, sarif_dir=sarif)
    assert code == 1
    assert "Regla REG-COD-001 (demo/**): 3 critical encontrados, 2 permitidos." in out


def test_excepcion_vencida_vuelve_a_contar(monkeypatch, capsys):
    # Al 2026-11-25 vence EXC-COD-2026-002: la alta de hash débil pasa a REG-COD-001 (3 de 5, sigue dentro).
    code, out = run_gate(monkeypatch, capsys, today="2026-11-25")
    assert code == 0
    assert "EXC-COD-2026-002 vencida" in out
    assert "| `REG-COD-001` | `demo/**` | `*` | high | 3 | 5 |" in out


def test_sin_sarif_falla(monkeypatch, capsys, tmp_path):
    code, out = run_gate(monkeypatch, capsys, sarif_dir=tmp_path)
    assert code == 1 and "No se encontraron archivos SARIF" in out


# ------------------------------------------------------------------------------- Validación del archivo de excepciones

def test_archivo_del_repo_es_valido():
    _, exceptions, rules, errors = gate.load_policy(EXCEPTIONS, TODAY)
    assert errors == [] and len(exceptions) == 5 and len(rules) == 3


def test_archivo_invalido_detecta_errores(monkeypatch, capsys, tmp_path):
    bad = tmp_path / "excepciones-codigo.yml"
    bad.write_text("""
excepciones:
  - id: EXC-X
    regla: py/command-line-injection
    ruta: "**"
    severidades: [critical]
    justificacion: "x"
    aprobado_por: "@a"
    vence: 2028-01-01
  - id: EXC-Y
    regla: py/sql-injection
    justificacion: "sin ruta ni aprobador"
reglas_por_ruta:
  - id: REG-X
    ruta: demo/**
    max: { urgent: 1, high: -2 }
    justificacion: "x"
""", encoding="utf-8")
    _, _, _, errors = gate.load_policy(bad, TODAY)
    text = "\n".join(errors)
    for expected in ["`ruta` demasiado amplia", "no permite exceptuar hallazgos `critical`", "supera el máximo de 90 días",
                     "falta `ruta`", "falta `aprobado_por`", "falta `vence`", "`max.urgent` inválido", "`max.high` inválido"]:
        assert expected in text, f"no se detectó: {expected}\n{text}"
    code, out = run_gate(monkeypatch, capsys, exceptions=bad)
    assert code == 1 and "errores de configuración" in out


def test_critico_nunca_se_exceptua():
    policy = dict(gate.DEFAULT_POLICY)
    exc = {"id": "E", "regla": "py/*", "ruta": "demo/**", "severidades": [], "vence": datetime.date(2027, 1, 1)}
    critical = {"rule": "py/command-line-injection", "path": "demo/a.py", "severity": "critical"}
    high = {"rule": "py/sql-injection", "path": "demo/a.py", "severity": "high"}
    assert gate.find_exception(critical, [exc], TODAY, policy) is None
    assert gate.find_exception(high, [exc], TODAY, policy) is exc
