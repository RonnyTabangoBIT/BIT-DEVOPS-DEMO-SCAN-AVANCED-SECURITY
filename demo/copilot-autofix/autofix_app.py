"""Demo para Copilot Autofix: vulnerabilidades INTENCIONALES que CodeQL detecta
y para las que Copilot Autofix propone un parche en el Pull Request.

NO desplegar.
"""
import base64
import hashlib
import pickle

from flask import Flask, jsonify, redirect, request

app = Flask(__name__)


# VULNERABLE: deserialización insegura (CodeQL py/unsafe-deserialization)
# Autofix esperado: reemplazar pickle por json.loads.
@app.route("/profile", methods=["POST"])
def load_profile():
    data = base64.b64decode(request.form["data"])
    profile = pickle.loads(data)
    return jsonify(profile)


# VULNERABLE: hash débil para contraseñas (CodeQL py/weak-sensitive-data-hashing)
# Autofix esperado: usar un KDF (p. ej. hashlib.pbkdf2_hmac / argon2) con salt.
@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    return jsonify(hash=hashlib.md5(password.encode()).hexdigest())


# VULNERABLE: redirección abierta (CodeQL py/url-redirection)
# Autofix esperado: validar que la URL sea relativa / del mismo host.
@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    return redirect(next_url)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
