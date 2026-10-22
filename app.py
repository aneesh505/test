"""
INTENTIONALLY VULNERABLE demo app fixed for security.
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

# Fixed VULN 1: use environment variables or secure defaults
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
API_KEY = os.environ.get("API_KEY", "sk-secure-placeholder")

DB_PATH = Path(__file__).parent / "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    # Fixed VULN 2: use SHA-256 instead of MD5
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
    # Fixed VULN 3: parameterized query
    query = (
        "SELECT * FROM users WHERE username = ? "
        "AND password = ?"
    )
    conn = get_db_connection()
    row = conn.execute(query, (username, hash_password(password))).fetchone()
    conn.close()
    if row:
        return jsonify(status="ok", user=row["username"], role=row["role"])
    return jsonify(status="denied"), 401

@app.get("/search")
def search():
    q = request.args.get("q", "")
    # Fixed VULN 4: parameterized query with LIKE
    query = "SELECT username FROM users WHERE username LIKE ?"
    conn = get_db_connection()
    rows = conn.execute(query, (f"%{q}%",)).fetchall()
    conn.close()
    return jsonify(results=[r["username"] for r in rows])

@app.get("/diagnose")
def diagnose():
    host = request.args.get("host", "localhost")
    # Fixed VULN 5: avoid shell=True, pass arguments as list
    cmd = [sys.executable, "-c", "import sys; print(sys.argv[1])", host]
    output = subprocess.check_output(cmd, text=True)
    return jsonify(output=output.strip())

@app.get("/hello")
def hello():
    name = request.args.get("name", "world")
    # Fixed VULN 6: use escape for XSS prevention
    return f"<h1>Hello {escape(name)}</h1>"

if __name__ == "__main__":
    # Fixed VULN 7: debug mode disabled
    app.run(debug=False)