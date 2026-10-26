"""
INTENTIONALLY VULNERABLE demo app, built only to test a security-fixing pipeline.
Run locally or inside a sandbox. NEVER deploy it. All secrets below are fake.
"""
import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from markupsafe import escape

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "super-secret-key-123")
API_KEY = os.environ.get("API_KEY", "sk-fake-1234567890abcdef")

DB_PATH = Path(__file__).parent / "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db_connection()
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    for name, pw, role in [("admin", "admin-pass", "admin"), ("alice", "alice-pass", "user")]:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (name, hash_password(pw), role),
        )
    conn.commit()
    conn.close()

init_db()

@app.get("/")
def index():
    return "Demo app is running"

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    conn = get_db_connection()
    row = conn.execute(query, (username, hash_password(password))).fetchone()
    conn.close()
    if row:
        return jsonify(status="ok", user=row["username"], role=row["role"])
    return jsonify(status="denied"), 401

@app.get("/search")
def search():
    q = request.args.get("q", "")
    query = "SELECT username FROM users WHERE username LIKE ?"
    conn = get_db_connection()
    rows = conn.execute(query, (f"%{q}%",)).fetchall()
    conn.close()
    return jsonify(results=[r["username"] for r in rows])

@app.get("/diagnose")
def diagnose():
    host = request.args.get("host", "localhost")
    try:
        output = subprocess.check_output(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", host],
            text=True,
            timeout=5,
        )
    except Exception as e:
        output = str(e)
    return jsonify(output=output.strip())

@app.get("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"<h1>Hello {escape(name)}</h1>"

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)