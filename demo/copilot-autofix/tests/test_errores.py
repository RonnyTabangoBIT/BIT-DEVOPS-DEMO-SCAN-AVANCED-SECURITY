"""Tests con entradas benignas: deben pasar antes y después de aplicar los parches de Copilot Autofix."""
from errores import command_injection, path_traversal, reflected_xss, sql_injection, stack_trace


def client(module):
    module.app.config["TESTING"] = True
    return module.app.test_client()


def test_sql_injection_finds_user():
    resp = client(sql_injection).get("/users?name=ana")
    assert resp.status_code == 200
    assert [u["name"] for u in resp.get_json()] == ["ana"]


def test_command_injection_echo():
    resp = client(command_injection).get("/echo?msg=hola")
    assert resp.status_code == 200
    assert "hola" in resp.get_data(as_text=True)


def test_path_traversal_reads_allowed_file():
    resp = client(path_traversal).get("/files?name=readme.txt")
    assert resp.status_code == 200
    assert "archivo de ejemplo" in resp.get_data(as_text=True)


def test_reflected_xss_greets():
    resp = client(reflected_xss).get("/hello?name=Ana")
    assert resp.status_code == 200
    assert "Hola Ana" in resp.get_data(as_text=True)


def test_stack_trace_divides():
    resp = client(stack_trace).get("/divide?a=6&b=3")
    assert resp.status_code == 200
    assert resp.get_json()["result"] == 2
