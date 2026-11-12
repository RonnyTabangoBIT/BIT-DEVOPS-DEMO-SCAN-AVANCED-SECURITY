# Dependabot – umbral de vulnerabilidades y control de excepciones

Demuestra cómo definir **cuántas vulnerabilidades se permiten por severidad**, cómo aceptar vulnerabilidades
de forma **controlada** (excepciones con aprobación y vencimiento) y cómo dar **umbrales distintos según la
versión** de una librería. El job `dependabot-severity-gate` falla cuando se supera cualquier umbral.

## Dependencias de la demo

| Manifiesto | Paquete | Vulnerabilidades |
|------------|---------|------------------|
| [`requirements.txt`](requirements.txt) | `jinja2==2.10` | 1 high + 5 medium |
| [`requirements.txt`](requirements.txt) | `requests==2.31.0` | 3 medium |

## Cómo se evalúa cada vulnerabilidad

El gate ([`severity_gate.py`](../../.github/scripts/severity_gate.py)) consulta la **GitHub Advisory Database**
y clasifica cada vulnerabilidad en este orden:

1. **Excepción vigente** ([`excepciones.yml`](../../.github/security/excepciones.yml) → `excepciones`): no cuenta.
2. **Regla por paquete y versión** (`reglas_por_paquete`): se evalúa contra el umbral propio de la regla.
3. **Umbral global** (`MAX_*` en el workflow): el resto.

| Variable del workflow | Valor | Significado |
|---|---:|---|
| `MAX_CRITICAL` | `0` | Críticas permitidas |
| `MAX_HIGH` | `2` | Altas permitidas |
| `MAX_MEDIUM` | `15` | Medias permitidas |
| `MAX_LOW` | `-1` | Bajas permitidas (vacío o `-1` = sin límite) |
| `EXCEPTIONS_FILE` | `.github/security/excepciones.yml` | Excepciones y reglas por paquete |

> 📘 **Cómo agregar una excepción**: paso a paso, todos los parámetros (para qué sirven y qué colocar) y errores
> frecuentes en [`.github/security/README.md`](../../.github/security/README.md).

## Excepciones

Una excepción acepta vulnerabilidades por **GHSA**, por **paquete**, por **rango de versiones** y/o por
**severidad**, con fecha de vencimiento:

```yaml
excepciones:
  - id: EXC-2026-001
    paquete: jinja2          # toda la librería...
    versiones: "==2.10"      # ...en esta versión...
    severidades: [medium]    # ...solo las medias
    justificacion: "..."
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2027-01-31
```

Política (bloque `politica`): vigencia máxima de **90 días**, aviso **15 días** antes de vencer, y las
`critical` **no se pueden exceptuar**. Si el archivo no cumple la política o le faltan campos, el gate **falla**.

| Estado en el resumen | Qué significa |
|---|---|
| ✅ Vigente | Se aplica |
| ⏳ Vence en N días | Se aplica, pero genera un aviso (`::warning`) |
| ⚠️ Vigente, sin coincidencias | No cubre ninguna vulnerabilidad: revisar si sigue siendo necesaria |
| ⛔ Vencida | **Ya no se aplica**: la vulnerabilidad vuelve a contar |

## Reglas por paquete y versión

Permiten un umbral distinto según la versión instalada. Reemplazan al umbral global para las severidades
que definen:

```yaml
reglas_por_paquete:
  - id: REG-001
    paquete: requests
    versiones: ">=2.31.0"
    max: { medium: 4 }      # versiones recientes: hasta 4 medias
  - id: REG-002
    paquete: requests
    versiones: "<2.31.0"
    max: { medium: 2 }      # versiones antiguas: solo 2 medias
```

## Flujo del control de excepciones

1. El gate falla porque una vulnerabilidad supera el umbral.
2. Primero se intenta **corregir** (actualizar la dependencia o aplicar el PR de Dependabot).
3. Si no se puede, se abre un **PR** que agrega la excepción a `excepciones.yml` con justificación y vencimiento.
4. El PR requiere la aprobación del **code owner** de `.github/security/` ([`CODEOWNERS`](../../.github/CODEOWNERS)).
5. Al hacer merge, el gate aplica la excepción automáticamente en los siguientes runs.
6. Al vencer, la excepción **deja de aplicarse sola** y el gate vuelve a fallar hasta corregir o renovar.
7. El historial de git de `excepciones.yml` deja la evidencia de quién pidió, quién aprobó y por qué.

## Resultado esperado (estado actual)

| Severidad | Encontradas | Exceptuadas | Por regla | Cuentan (global) | Permitidas | Estado |
|---|---:|---:|---:|---:|---:|---|
| Críticas | 0 | 0 | 0 | 0 | 0 | ✅ |
| Altas | 1 | 1 (`EXC-2026-002`) | 0 | 0 | 2 | ✅ |
| Medias | 8 | 5 (`EXC-2026-001`) | 3 (`REG-001`: 3 de 4) | 0 | 15 | ✅ |

Además, aparece un aviso porque `EXC-2026-002` vence pronto, y otro porque `EXC-2026-003` está vencida
(su vulnerabilidad vuelve a contar dentro de `REG-001`).

**Para ver los fallos:**

| Cambio | Resultado |
|---|---|
| `requests==2.30.0` en `requirements.txt` | ❌ `REG-002`: 4 medias de 2 permitidas |
| Dejar vencer `EXC-2026-002` con `MAX_HIGH: 0` | ❌ La alta de jinja2 vuelve a contar en el umbral global |
| Exceptuar una `critical` o poner `vence` a más de 90 días | ❌ Archivo de excepciones inválido |

> Los conteos dependen de la Advisory Database al momento de ejecutar y pueden crecer con nuevas advisories.

### Probar en local

```bash
pip install packaging pyyaml
MAX_CRITICAL=0 MAX_HIGH=2 MAX_MEDIUM=15 python .github/scripts/severity_gate.py   # desde la raíz
GATE_TODAY=2026-11-25 MAX_HIGH=0 python .github/scripts/severity_gate.py          # simula el vencimiento
```
