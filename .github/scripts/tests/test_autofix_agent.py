"""Pruebas de la lógica del Autofix Agent (sin llamar a la API)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import autofix_agent as agent  # noqa: E402


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
