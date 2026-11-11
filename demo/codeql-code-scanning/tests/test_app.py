import pytest

from app import app as app_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "test.db"))
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_users_safe(client):
    resp = client.get("/users/safe?name=alice")
    assert resp.get_json() == [{"id": 1, "name": "alice"}]


def test_hello(client):
    assert b"Hello world" in client.get("/hello").data
