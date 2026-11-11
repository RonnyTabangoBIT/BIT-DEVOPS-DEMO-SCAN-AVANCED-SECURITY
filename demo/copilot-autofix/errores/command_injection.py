import subprocess

from flask import Flask, request

app = Flask(__name__)


# VULNERABLE: inyección de comandos (CodeQL py/command-line-injection)
# Autofix esperado: pasar argumentos como lista y sin shell=True.
@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    return subprocess.check_output("echo " + msg, shell=True, text=True)
