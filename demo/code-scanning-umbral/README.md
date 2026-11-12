# Code scanning – superar el umbral y corregirlo

Esta carpeta muestra los dos lados del control de code scanning:

| Rama | Estado de [`app_umbral.py`](app_umbral.py) | Resultado del pipeline |
|---|---|---|
| Flujo en **rojo** (`feature/demo-app-advanced-security-serveral-minimal`) | Hallazgos intencionales **sin excepción** | ❌ El gate y el check *Code scanning results* fallan |
| Flujo en **verde** (esta rama) | Los mismos endpoints **corregidos** | ✅ Todo en verde |

## Flujo en rojo: hallazgos que superan el umbral

| Ruta | Regla de CodeQL | Severidad |
|---|---|---|
| `GET /calc` | `py/code-injection` (`eval`) | critical |
| `GET /dns` | `py/command-line-injection` (`shell=True`) | critical |
| `POST /session` | `py/unsafe-deserialization` (`pickle.loads`) | critical |
| `POST /session` | `py/reflective-xss` (devuelve el objeto como texto) | high |
| `GET /orders` | `py/sql-injection` | high |

Fallan **dos** controles distintos:

1. **Code scanning severidad mínima** (nuestro gate): la carpeta está en `demo/**` y cuenta contra `REG-COD-001`
   (`max: { critical: 2, ... }`), que queda en **5 de 2 críticas**.
2. **Code scanning results / CodeQL** (check automático de GitHub): falla con cualquier alerta **nueva** de severidad
   alta o crítica que introduzca el PR. **No lee `excepciones-codigo.yml`**, así que las excepciones no lo ponen en verde.

## Flujo en verde: corrección

| Ruta | Corrección |
|---|---|
| `GET /calc` | Evalúa solo números y `+ - * /` con `ast`, sin `eval` |
| `GET /dns` | Valida el host y lo resuelve con `socket.gethostbyname`, sin ejecutar comandos |
| `POST /session` | `json.loads` en lugar de `pickle`, y respuesta con `jsonify` |
| `GET /orders` | Consulta parametrizada (`?`) y respuesta con `jsonify` |

Con el código corregido CodeQL no genera alertas nuevas, el gate queda dentro del umbral sin excepciones y el check de
GitHub pasa. **Corregir es la única forma de dejar en verde ambos controles**: un cupo o una excepción solo satisfacen
nuestro gate, y las críticas no se pueden exceptuar.
