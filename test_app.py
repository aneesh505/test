"""Normal behaviour tests. These must pass before AND after any security fix."""
import pytest
from app import app, init_db


@pytest.fixture
def client():
    init_db()
    app.config["TESTING"] = True
    return app.test_client()


def test_index(client):
    assert client.get("/").status_code == 200


def test_login_valid(client):
    r = client.post("/login", json={"username": "admin", "password": "admin-pass"})
    assert r.status_code == 200
    assert r.get_json()["role"] == "admin"


def test_login_wrong_password(client):
    r = client.post("/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_search_finds_user(client):
    r = client.get("/search", query_string={"q": "ali"})
    assert r.get_json()["results"] == ["alice"]


def test_diagnose_normal_host(client):
    r = client.get("/diagnose", query_string={"host": "localhost"})
    assert r.get_json()["output"] == "localhost"


def test_hello_greets(client):
    r = client.get("/hello", query_string={"name": "Aneesh"})
    assert "Hello Aneesh" in r.get_data(as_text=True)
