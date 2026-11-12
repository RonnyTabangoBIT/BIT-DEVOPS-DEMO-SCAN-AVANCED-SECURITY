"""Errores INTENCIONALES para que el gate "Code scanning severidad mínima" SUPERE EL UMBRAL y falle el pipeline.

Estos hallazgos NO tienen excepción en .github/security/excepciones-codigo.yml: cuentan contra el cupo de
REG-COD-001 (demo/**), que permite como máximo 2 críticas. Con este archivo hay 5 críticas -> el job falla.

Para que el pipeline vuelva a pasar: corregir el código (por ejemplo con Copilot Autofix) o borrar esta carpeta.
NO desplegar.
"""
import base64
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


# CRITICAL: inyección de código (CodeQL py/code-injection)
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


# CRITICAL: inyección de comandos (CodeQL py/command-line-injection)
@app.route("/dns")
def dns():
    host = request.args.get("host", "localhost")
    return subprocess.check_output("nslookup " + host, shell=True, text=True)


# CRITICAL: deserialización insegura (CodeQL py/unsafe-deserialization)
@app.route("/session", methods=["POST"])
def session():
    return str(pickle.loads(base64.b64decode(request.form["data"])))


# HIGH: inyección SQL (CodeQL py/sql-injection)
@app.route("/orders")
def orders():
    customer = request.args.get("customer", "")
    conn = sqlite3.connect(":memory:")
    return str(conn.execute("SELECT * FROM orders WHERE customer = '" + customer + "'").fetchall())
