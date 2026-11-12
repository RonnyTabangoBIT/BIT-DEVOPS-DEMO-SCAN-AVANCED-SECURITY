# Code scanning – superar el umbral (pipeline en rojo)

[`app_umbral.py`](app_umbral.py) contiene hallazgos **intencionales** que **no tienen excepción** en
[`excepciones-codigo.yml`](../../.github/security/excepciones-codigo.yml). Sirve para mostrar que el gate
**Code scanning severidad mínima** bloquea el merge cuando se supera el umbral.

| Ruta | Regla de CodeQL | Severidad |
|---|---|---|
| `GET /calc` | `py/code-injection` (`eval`) | critical |
| `GET /dns` | `py/command-line-injection` (`shell=True`) | critical |
| `POST /session` | `py/unsafe-deserialization` (`pickle.loads`) | critical |
| `GET /orders` | `py/sql-injection` | high |

## Resultado esperado

La carpeta está dentro de `demo/**`, así que sus hallazgos cuentan contra la regla `REG-COD-001`
(`max: { critical: 2, high: 5, medium: 3 }`):

| Severidad | Antes | Con esta carpeta | Permitidas | Estado |
|---|---:|---:|---:|---|
| critical | 2 | **5** | 2 | ❌ Supera el umbral |
| high | 2 | 3 | 5 | ✅ |

El job termina con *"❌ El gate falla (regla REG-COD-001 (critical))"*, marca cada hallazgo en la línea del código
(`::error`) y el ruleset de `main` impide el merge.

## Cómo volver a verde

Elegir una opción (una excepción no alcanza para las críticas: la política no permite exceptuar hallazgos `critical`):

1. **Corregir el código**, por ejemplo aplicando las sugerencias de Copilot Autofix.
2. **Borrar esta carpeta.**
3. **Darle un cupo propio a la carpeta y exceptuar lo que se pueda** en
   [`excepciones-codigo.yml`](../../.github/security/excepciones-codigo.yml). Es lo que hace la rama del **flujo en verde**:

   | Entrada | Qué cubre | Resultado |
   |---|---|---|
   | `REG-COD-003` (regla por ruta, antes de `REG-COD-001`) | `demo/code-scanning-umbral/**`: hasta 3 critical y 1 high | Las 3 críticas quedan dentro del cupo (3 de 3) |
   | `EXC-COD-2026-005` (excepción) | `py/sql-injection` (high) en `app_umbral.py` | La alta queda exceptuada |

   Con eso `REG-COD-001` vuelve a 2 de 2 críticas y el job pasa en verde.
