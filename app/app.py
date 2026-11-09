"""Demo app with INTENTIONAL vulnerabilities to exercise GitHub Advanced Security.

DO NOT deploy this application. It exists only to generate code scanning alerts.
"""
import os
import sqlite3
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "demo.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO users (name) VALUES (?)", [("alice",), ("bob",)]
            )


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/users/safe")
def users_safe():
    name = request.args.get("name", "")
    with get_db() as conn:
        rows = conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
    return jsonify([dict(r) for r in rows])


# VULNERABLE: SQL injection (CodeQL py/sql-injection)
@app.route("/users")
def users():
    name = request.args.get("name", "")
    with get_db() as conn:
        rows = conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
    return jsonify([dict(r) for r in rows])


# VULNERABLE: command injection (CodeQL py/command-line-injection)
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return output.stdout


# VULNERABLE: reflected XSS (CodeQL py/reflective-xss)
@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"<h1>Hello {name}</h1>"


# VULNERABLE: path traversal (CodeQL py/path-injection)
@app.route("/files")
def read_file():
    filename = request.args.get("name", "")
    with open(os.path.join("data", filename)) as f:
        return f.read()


if __name__ == "__main__":
    init_db()
    # VULNERABLE: debug mode enabled (CodeQL py/flask-debug)
    app.run(host="0.0.0.0", port=5000, debug=True)
