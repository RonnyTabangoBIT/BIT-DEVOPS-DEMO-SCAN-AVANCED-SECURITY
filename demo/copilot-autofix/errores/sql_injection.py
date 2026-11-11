import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.executemany("INSERT INTO users (name) VALUES (?)", [("ana",), ("luis",)])
    return conn


# VULNERABLE: inyección SQL (CodeQL py/sql-injection)
# Autofix esperado: consulta parametrizada con "?".
@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    rows = get_db().execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
    return jsonify([{"id": r[0], "name": r[1]} for r in rows])
