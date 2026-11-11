from flask import Flask, request

app = Flask(__name__)


# VULNERABLE: XSS reflejado (CodeQL py/reflective-xss)
# Autofix esperado: escapar la entrada con markupsafe.escape.
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<h1>Hola {name}</h1>"


if __name__ == "__main__":
    # VULNERABLE: modo debug activo (CodeQL py/flask-debug)
    # Autofix esperado: debug=False o controlado por variable de entorno.
    app.run(debug=True)
