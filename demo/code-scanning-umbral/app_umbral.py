"""Versión CORREGIDA de los hallazgos que superaban el umbral de code scanning (flujo en verde).

En la rama del flujo en rojo este archivo tenía 3 críticas y 2 altas de CodeQL (code injection, command injection,
unsafe deserialization, XSS reflejado y SQL injection). Aquí cada endpoint está corregido, así que CodeQL no
genera alertas nuevas y tanto el gate "Code scanning severidad mínima" como el check "Code scanning results" pasan.
"""
import ast
import json
import operator
import re
import socket
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

_OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _evaluate(node):
    """Evalúa solo números y + - * / (sin eval)."""
    if isinstance(node, ast.Expression):
        return _evaluate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
        return _OPERATORS[type(node.op)](_evaluate(node.left), _evaluate(node.right))
    raise ValueError("expresión no permitida")


# CORREGIDO (antes py/code-injection con eval): solo aritmética básica con el árbol de sintaxis.
@app.route("/calc")
def calc():
    try:
        result = _evaluate(ast.parse(request.args.get("expr", "1+1"), mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError):
        return jsonify(error="expresión inválida"), 400
    return jsonify(result=result)


# CORREGIDO (antes py/command-line-injection con shell=True): resolución DNS sin ejecutar comandos.
@app.route("/dns")
def dns():
    host = request.args.get("host", "localhost")
    if not _HOSTNAME.fullmatch(host):
        return jsonify(error="host inválido"), 400
    try:
        return jsonify(host=host, address=socket.gethostbyname(host))
    except OSError:
        return jsonify(error="no se pudo resolver"), 404


# CORREGIDO (antes py/unsafe-deserialization con pickle y XSS reflejado): JSON y respuesta JSON.
@app.route("/session", methods=["POST"])
def session():
    try:
        data = json.loads(request.form.get("data", "{}"))
    except ValueError:
        return jsonify(error="JSON inválido"), 400
    return jsonify(session=data)


# CORREGIDO (antes py/sql-injection): consulta parametrizada.
@app.route("/orders")
def orders():
    customer = request.args.get("customer", "")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer TEXT)")
    rows = conn.execute("SELECT id, customer FROM orders WHERE customer = ?", (customer,)).fetchall()
    return jsonify(orders=[{"id": r[0], "customer": r[1]} for r in rows])
