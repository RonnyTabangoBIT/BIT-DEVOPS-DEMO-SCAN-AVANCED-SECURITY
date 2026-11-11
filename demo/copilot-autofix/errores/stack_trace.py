import traceback

from flask import Flask, jsonify, request

app = Flask(__name__)


# VULNERABLE: exposición de stack trace (CodeQL py/stack-trace-exposure)
# Autofix esperado: registrar el error en el log y devolver un mensaje genérico.
@app.route("/divide")
def divide():
    try:
        a = int(request.args.get("a", "0"))
        b = int(request.args.get("b", "1"))
        return jsonify(result=a / b)
    except Exception:
        return traceback.format_exc(), 500
