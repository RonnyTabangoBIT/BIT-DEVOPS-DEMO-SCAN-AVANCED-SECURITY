"""Pruebas de la lógica del agente de Autofix y de la auditoría de excepciones (sin llamar a la API)."""
import datetime
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import autofix_agent as agent  # noqa: E402
import security_exceptions_audit as audit  # noqa: E402

POLICY = yaml.safe_load((Path(__file__).resolve().parents[2] / "security" / "politica-descartes.yml").read_text(encoding="utf-8"))
NOW = datetime.datetime(2026, 11, 12, tzinfo=datetime.timezone.utc)
OWNER = {"login": "RonnyTabangoBIT"}


# ------------------------------------------------------------------------------- Autofix agent

def cs_alert(number, level, state="open", tool="CodeQL", rule_id="py/sql-injection"):
    return {"number": number, "state": state, "tool": {"name": tool}, "html_url": f"https://x/{number}",
            "rule": {"id": rule_id, "security_severity_level": level},
            "most_recent_instance": {"location": {"path": "app.py", "start_line": 10}}}


def test_select_alerts_filtra_por_severidad_estado_y_herramienta():
    alerts = [cs_alert(1, "medium"), cs_alert(2, "critical"), cs_alert(3, "high"),
              cs_alert(4, "high", state="dismissed"), cs_alert(5, "critical", tool="Semgrep"), cs_alert(6, None)]
    assert [a["number"] for a in agent.select_alerts(alerts, "high", 10)] == [2, 3]


def test_select_alerts_respeta_el_maximo_y_ordena_por_severidad():
    alerts = [cs_alert(n, lvl) for n, lvl in [(1, "high"), (2, "critical"), (3, "high"), (4, "critical")]]
    assert [a["number"] for a in agent.select_alerts(alerts, "high", 3)] == [2, 4, 1]


def test_requisitos_repo_publico_con_codeql():
    reqs = agent.evaluate_requirements(
        {"visibility": "public"}, (200, [{"created_at": "2026-11-12T00:00:00Z"}]),
        (200, {"state": "not-configured"}), {"Python": 100, "HTML": 5})
    assert {r["name"]: r["status"] for r in reqs} == {
        "Licencia": "✅", "Code scanning con CodeQL": "✅", "Modo de configuración": "✅", "Lenguajes soportados": "✅"}


def test_requisitos_detectan_problemas():
    reqs = agent.evaluate_requirements(
        {"visibility": "private"}, (404, {"message": "no analysis found"}),
        (200, {"state": "configured"}), {"HCL": 10})
    status = {r["name"]: r["status"] for r in reqs}
    assert status["Licencia"] == "⚠️"
    assert status["Code scanning con CodeQL"] == "❌"
    assert status["Modo de configuración"] == "⚠️"     # default setup en conflicto con el workflow
    assert status["Lenguajes soportados"] == "⚠️"


def test_requisito_default_setup_no_verificable_con_github_token():
    reqs = agent.evaluate_requirements({"visibility": "public"}, (200, [{}]), (403, {"message": "Forbidden"}), {"Python": 1})
    assert next(r for r in reqs if r["name"] == "Modo de configuración")["status"] == "⚠️"


# ------------------------------------------------------------------------------- Auditoría: code scanning

def dismissed(number, reason, comment, by=OWNER, level="high", approved=None):
    a = cs_alert(number, level, state="dismissed")
    a.update({"dismissed_reason": reason, "dismissed_comment": comment, "dismissed_by": by,
              "dismissed_at": "2026-11-10T12:00:00Z", "dismissal_approved_by": approved})
    return a


def test_code_scanning_descarte_valido():
    rows = audit.evaluate_code_scanning(
        [dismissed(1, "won't fix", "EXC-2026-010: solo corre en el entorno local de pruebas")], POLICY)
    assert rows[0]["cumple"], rows[0]["problemas"]


def test_code_scanning_falso_positivo_no_requiere_id():
    rows = audit.evaluate_code_scanning(
        [dismissed(2, "false positive", "El input se valida con una lista blanca antes del sink")], POLICY)
    assert rows[0]["cumple"], rows[0]["problemas"]


@pytest.mark.parametrize("alert, problema", [
    (dismissed(3, "won't fix", ""), "justificación menor"),
    (dismissed(4, "won't fix", "No se va a corregir en este sprint, bajo riesgo"), "falta el ID de excepción"),
    (dismissed(5, "false positive", "Es un falso positivo de la query", by={"login": "otro-usuario"}), "no está en la lista de aprobadores"),
])
def test_code_scanning_descartes_que_no_cumplen(alert, problema):
    rows = audit.evaluate_code_scanning([alert], POLICY)
    assert not rows[0]["cumple"]
    assert problema in rows[0]["problemas"]


def test_code_scanning_aprobacion_delegada_requerida_para_high():
    policy = yaml.safe_load(yaml.safe_dump(POLICY))
    policy["code_scanning"]["requiere_aprobacion_delegada"] = True
    sin = audit.evaluate_code_scanning([dismissed(6, "false positive", "Validado por el equipo de seguridad")], policy)
    con = audit.evaluate_code_scanning(
        [dismissed(7, "false positive", "Validado por el equipo de seguridad", approved={"login": "seguridad"})], policy)
    assert not sin[0]["cumple"] and "aprobación delegada" in sin[0]["problemas"]
    assert con[0]["cumple"] and con[0]["aprobado_por"] == "seguridad"


def test_code_scanning_ignora_alertas_abiertas():
    assert audit.evaluate_code_scanning([cs_alert(8, "high")], POLICY) == []


# ------------------------------------------------------------------------------- Auditoría: secret scanning

def secret(number, state="resolved", resolution=None, comment="", by=OWNER, bypassed_at=None):
    return {"number": number, "state": state, "secret_type_display_name": "GitHub Personal Access Token",
            "html_url": f"https://x/s/{number}", "resolution": resolution, "resolution_comment": comment,
            "resolved_by": by, "resolved_at": "2026-11-10T12:00:00Z",
            "push_protection_bypassed": bypassed_at is not None, "push_protection_bypassed_at": bypassed_at,
            "push_protection_bypassed_by": by, "push_protection_bypass_request_comment": comment}


def test_secret_revocado_siempre_cumple():
    rows = audit.evaluate_secret_scanning([secret(1, resolution="revoked")], POLICY, NOW)
    assert rows[0]["cumple"]


def test_secret_usado_en_tests_requiere_id_de_excepcion():
    sin_id = audit.evaluate_secret_scanning(
        [secret(2, resolution="used_in_tests", comment="Token falso usado en los tests unitarios")], POLICY, NOW)
    con_id = audit.evaluate_secret_scanning(
        [secret(3, resolution="used_in_tests", comment="EXC-2026-011: token falso de los tests unitarios")], POLICY, NOW)
    assert not sin_id[0]["cumple"] and "ID de excepción" in sin_id[0]["problemas"]
    assert con_id[0]["cumple"]


def test_secret_bypass_abierto_fuera_de_plazo():
    reciente = audit.evaluate_secret_scanning([secret(4, state="open", bypassed_at="2026-11-10T00:00:00Z")], POLICY, NOW)
    viejo = audit.evaluate_secret_scanning([secret(5, state="open", bypassed_at="2026-10-01T00:00:00Z")], POLICY, NOW)
    assert reciente[0]["cumple"] and reciente[0]["motivo"] == "bypass push protection"
    assert not viejo[0]["cumple"] and "tras el bypass" in viejo[0]["problemas"]


def test_secret_abierto_sin_bypass_no_es_excepcion():
    assert audit.evaluate_secret_scanning([secret(6, state="open")], POLICY, NOW) == []


# ------------------------------------------------------------------------------- Casos simulados (errores de la política)

SECURITY_DIR = Path(__file__).resolve().parents[2] / "security"
FIXTURES = json.loads((SECURITY_DIR / "pruebas" / "descartes-simulados.json").read_text(encoding="utf-8"))
FIXTURE_NOW = datetime.datetime.fromisoformat(FIXTURES["fecha_referencia"]).replace(tzinfo=datetime.timezone.utc)
CASES = [("code_scanning", a) for a in FIXTURES["code_scanning"]] + [("secret_scanning", a) for a in FIXTURES["secret_scanning"]]


@pytest.mark.parametrize("tipo, alerta", CASES, ids=[f"#{a['number']} {a['_caso']}" for _, a in CASES])
def test_descartes_simulados_dan_el_resultado_esperado(tipo, alerta):
    if tipo == "code_scanning":
        rows = audit.evaluate_code_scanning([alerta], POLICY)
    else:
        rows = audit.evaluate_secret_scanning([alerta], POLICY, FIXTURE_NOW)
    assert len(rows) == 1
    esperado = alerta["_esperado"]
    assert rows[0]["cumple"] is esperado["cumple"], rows[0]["problemas"]
    for problema in esperado.get("problemas", []):
        assert problema in rows[0]["problemas"]


def test_simulacion_tiene_casos_validos_y_con_error():
    resultados = [a["_esperado"]["cumple"] for _, a in CASES]
    assert resultados.count(True) >= 4 and resultados.count(False) >= 7


def test_main_en_modo_simulacion_falla_y_genera_registro(tmp_path, monkeypatch):
    csv_path = tmp_path / "registro.csv"
    monkeypatch.chdir(Path(__file__).resolve().parents[3])
    monkeypatch.setenv("AUDIT_FIXTURES", str(SECURITY_DIR / "pruebas" / "descartes-simulados.json"))
    monkeypatch.setenv("AUDIT_CSV", str(csv_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "RonnyTabangoBIT/demo")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GATE_TODAY", raising=False)
    with pytest.raises(SystemExit) as exc:
        audit.main()
    assert exc.value.code == 1
    lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1 + len(CASES)          # encabezado + un registro por descarte


# ------------------------------------------------------------------------------- Validación del archivo de política

def test_politica_del_repo_es_valida():
    assert audit.validate_policy(POLICY) == []


def test_politica_invalida_detecta_cada_error():
    invalid = yaml.safe_load((SECURITY_DIR / "pruebas" / "politica-invalida.yml").read_text(encoding="utf-8"))
    errores = "\n".join(audit.validate_policy(invalid))
    for esperado in [
        "`formato_id_excepcion` no es una expresión regular válida",
        "`code_scanning.motivos_permitidos` tiene valores que no existen en la API: ['accepted risk']",
        "`code_scanning.comentario_minimo` debe ser un entero >= 0",
        "`code_scanning.requiere_id_excepcion` incluye motivos no permitidos",
        "`code_scanning.aprobadores` debe ser una lista",
        "`code_scanning.severidades_con_aprobacion` tiene severidades inválidas: ['urgent']",
        "`secret_scanning.resoluciones_permitidas` tiene valores que no existen en la API: ['wontfix']",
        "`secret_scanning.requiere_id_excepcion` incluye motivos no permitidos",
        "`secret_scanning.dias_maximos_abierta_tras_bypass` debe ser un entero",
    ]:
        assert esperado in errores, f"no se detectó: {esperado}\n{errores}"


def test_main_con_politica_invalida_no_evalua_y_falla(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(Path(__file__).resolve().parents[3])
    monkeypatch.setenv("POLICY_FILE", str(SECURITY_DIR / "pruebas" / "politica-invalida.yml"))
    monkeypatch.setenv("AUDIT_FIXTURES", str(SECURITY_DIR / "pruebas" / "descartes-simulados.json"))
    monkeypatch.setenv("AUDIT_CSV", str(tmp_path / "registro.csv"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    with pytest.raises(SystemExit) as exc:
        audit.main()
    salida = capsys.readouterr().out
    assert exc.value.code == 1
    assert "El archivo de política es inválido" in salida
    assert "No se evaluaron los descartes" in salida
    assert "Todas las excepciones cumplen" not in salida
