import os

from flask import Flask, request

app = Flask(__name__)
BASE_DIR = os.path.join(os.path.dirname(__file__), "files")


# VULNERABLE: path traversal (CodeQL py/path-injection)
# Autofix esperado: normalizar la ruta y verificar que quede dentro de BASE_DIR.
@app.route("/files")
def read_file():
    name = request.args.get("name", "")
    with open(os.path.join(BASE_DIR, name), encoding="utf-8") as fh:
        return fh.read()
