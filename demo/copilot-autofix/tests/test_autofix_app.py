import pytest

import autofix_app


@pytest.fixture
def client():
    autofix_app.app.config["TESTING"] = True
    with autofix_app.app.test_client() as c:
        yield c


# Payloads benignos: los tests deben pasar antes y después de aplicar los parches de Autofix.
def test_login_relative_redirect(client):
    resp = client.get("/login?next=/home")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/home")


def test_register_returns_hash(client):
    resp = client.post("/register", data={"password": "s3cret"})
    assert resp.status_code == 200
    assert resp.get_json()["hash"]
