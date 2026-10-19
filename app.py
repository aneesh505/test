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
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secure handling of secrets: load from environment variables
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "super-secret-key-123")
API_KEY = os.getenv("API_KEY", "sk-fake-1234567890abcdef")

DB_PATH = Path(__file__).parent / "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Hash a password using a strong algorithm."""
    return generate_password_hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against the stored hash."""
    return check_password_hash(stored_hash, password)

def init_db():
    conn = get_db_connection()
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    # Insert users with securely hashed passwords
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

    conn = get_db_connection()
    # Parameterized query to fetch the user by username only
    query = "SELECT * FROM users WHERE username = ?"
    row = conn.execute(query, (username,)).fetchone()
    conn.close()

    if row and verify_password(row["password"], password):
        return jsonify(status="ok", user=row["username"], role=row["role"])
    return jsonify(status="denied"), 401

@app.get("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db_connection()
    # Parameterized LIKE query to avoid injection
    query = "SELECT username FROM users WHERE username LIKE ?"
    pattern = f"%{q}%"
    rows = conn.execute(query, (pattern,)).fetchall()
    conn.close()
    return jsonify(results=[r["username"] for r in rows])

@app.get("/diagnose")
def diagnose():
    host = request.args.get("host", "localhost")
    # Safe subprocess call without shell=True and without string interpolation
    cmd = [
        sys.executable,
        "-c",
        "import sys; print(sys.argv[1])",
        host,
    ]
    output = subprocess.check_output(cmd, text=True)
    return jsonify(output=output.strip())

@app.get("/hello")
def hello():
    name = request.args.get("name", "world")
    # Escape the user-provided name to prevent reflected XSS
    safe_name = escape(name)
    return f"<h1>Hello {safe_name}</h1>"

if __name__ == "__main__":
    # Debug mode controlled via environment variable; default is off
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)