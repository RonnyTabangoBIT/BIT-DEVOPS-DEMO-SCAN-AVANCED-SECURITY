# Guía de excepciones de seguridad

Esta carpeta contiene los dos archivos con los que se **aceptan vulnerabilidades de forma controlada**. Ambos funcionan igual:
cada entrada tiene justificación, aprobador y **fecha de vencimiento**, se agrega **por Pull Request** y requiere la aprobación
del code owner (ver [`CODEOWNERS`](../CODEOWNERS)).

| Archivo | Qué controla | Job que lo aplica |
|---|---|---|
| [`excepciones.yml`](excepciones.yml) | Vulnerabilidades de **librerías** (dependencias pip) | `Dependabot severidad mínima` |
| [`excepciones-codigo.yml`](excepciones-codigo.yml) | Hallazgos de **código** (CodeQL) | `Code scanning severidad mínima` |

Cada job revisa cada vulnerabilidad en este orden:

1. ¿Tiene una **excepción vigente**? → no cuenta.
2. ¿Tiene una **regla de cupo** (`reglas_por_paquete` / `reglas_por_ruta`)? → cuenta contra el cupo de la regla.
3. Si no → cuenta contra el **umbral global** (`MAX_CRITICAL`, `MAX_HIGH`, `MAX_MEDIUM`, `MAX_LOW` en el workflow).

Si se supera algún umbral, o si el archivo tiene errores, el job falla y **no se puede hacer merge**.

**Reglas que valen para los dos archivos**

- Las vulnerabilidades **`critical` nunca se exceptúan**: hay que corregirlas.
- Ninguna excepción puede durar más de **90 días**. El job avisa **15 días antes** del vencimiento y, al vencer, la excepción
  **deja de aplicarse sola**.
- **Primero se intenta corregir**: la excepción es el último recurso.
- Las fechas van en formato `AAAA-MM-DD` y los textos, entre comillas.

---

## Excepciones de librerías

Archivo: [`.github/security/excepciones.yml`](excepciones.yml) · Job: **Dependabot severidad mínima**

**Paso a paso**

1. **Identificar la vulnerabilidad.** En el PR, abrir el job *Dependabot severidad mínima* → *Summary* → tabla **Detalle**. Ahí están el `Paquete` (`nombre==versión`), la `Severidad` y el `Advisory` (ID GHSA).
2. **Intentar corregir primero**: subir la versión de la librería en el manifiesto. La excepción es el último recurso.
3. **Si no se puede corregir**, crear una rama y agregar una entrada en `excepciones.yml`:
   - bajo `excepciones:` para **aceptar** vulnerabilidades concretas (con vencimiento), o
   - bajo `reglas_por_paquete:` para darle a una librería un **cupo** propio de vulnerabilidades según su versión.
4. **Abrir un PR.** El gate valida el archivo: si falta un campo o no cumple la política, el job falla y lista los errores.
5. **Aprobación**: el PR requiere la revisión del code owner de `.github/security/` (CODEOWNERS). Con la aprobación y los checks en verde, se hace merge.
6. **Desde el merge**, el gate deja de contar lo que cubre la excepción: en la tabla **Detalle** aparece como *Exceptuada (`EXC-…`)* y la tabla **Control de excepciones** muestra su estado.
7. **Antes de que venza** (el job avisa 15 días antes): corregir la dependencia o **renovar** con un nuevo PR que actualice `vence` y `justificacion`. Cuando la vulnerabilidad se corrige, **borrar la entrada**; el gate avisa *"Vigente, sin coincidencias"* si queda una excepción que ya no cubre nada.

**Parámetros de una excepción** (lista `excepciones:`)

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la excepción en el resumen, en los avisos y en el historial de git | Código único en todo el archivo (no puede repetirse, tampoco con una regla). Convención: `EXC-AAAA-NNN` (año + correlativo) | `EXC-2026-004` |
| `paquete` | Sí, si no se indica `ghsa` | Limita la excepción a una librería | Nombre de la librería como está en el manifiesto. No distingue mayúsculas, guiones ni guiones bajos | `jinja2` |
| `ghsa` | Sí, si no se indica `paquete` | Limita la excepción a **una** vulnerabilidad | ID del advisory, columna *Advisory* del resumen | `GHSA-462w-v97r-4m45` |
| `versiones` | No | Limita la excepción a ciertas versiones de la librería | Rango de versiones de Python (PEP 440) **entre comillas**; varias condiciones separadas por coma. Si se omite, aplica a cualquier versión | `"==2.10"` · `">=2.0,<3.0"` |
| `severidades` | No | Limita la excepción a ciertas severidades | Lista con `high`, `medium` y/o `low`. **`critical` no se permite.** Si se omite, aplica a todas excepto `critical` | `[medium]` · `[high, medium]` |
| `justificacion` | Sí | Deja registrado por qué se acepta el riesgo | Texto **entre comillas** con el motivo concreto, la mitigación y el plan de corrección | `"El sandbox no se usa con plantillas de usuarios; migración a jinja2 3.x en el sprint 24."` |
| `solicitado_por` | No | Trazabilidad: quién pidió la excepción | Usuario de GitHub con `@`, entre comillas | `"@dev-backend"` |
| `aprobado_por` | Sí | Trazabilidad: quién aceptó el riesgo | Usuario del code owner que aprueba el PR, entre comillas. La aprobación efectiva es la revisión del PR | `"@RonnyTabangoBIT"` |
| `vence` | Sí | Hace que la excepción sea **temporal** | Fecha `AAAA-MM-DD` sin comillas, como máximo **hoy + 90 días**. La excepción se aplica hasta ese día incluido | `2027-01-31` |

La excepción se aplica solo si se cumplen **todas** las condiciones que se indiquen (`paquete`, `ghsa`, `versiones` y `severidades`). Combinaciones habituales:

| Quiero exceptuar… | Parámetros |
|---|---|
| Una vulnerabilidad puntual | `ghsa` |
| Una vulnerabilidad puntual, solo en la versión instalada | `ghsa` + `versiones` |
| Todas las vulnerabilidades de una librería, de cierta severidad, en una versión | `paquete` + `versiones` + `severidades` |

Ejemplos:

```yaml
excepciones:
  # Una vulnerabilidad puntual
  - id: EXC-2026-002
    ghsa: GHSA-462w-v97r-4m45
    justificacion: "Actualización a jinja2 3.x planificada para el próximo sprint."
    solicitado_por: "@RonnyTabangoBIT"
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2026-11-20

  # Todas las medias de una librería en una versión
  - id: EXC-2026-001
    paquete: jinja2
    versiones: "==2.10"
    severidades: [medium]
    justificacion: "El sandbox de Jinja2 no se usa con plantillas de usuarios."
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2027-01-31
```

**Parámetros de una regla por paquete** (lista `reglas_por_paquete:`)

Una regla no acepta vulnerabilidades concretas: le da a una librería un **cupo** propio por severidad, que reemplaza al umbral global (`MAX_*`) para esa librería. Sirve, por ejemplo, para tolerar más vulnerabilidades en versiones recientes que en versiones antiguas.

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la regla en el resumen | Código único en el archivo. Convención: `REG-NNN` | `REG-003` |
| `paquete` | Sí | Librería a la que aplica el cupo | Nombre como en el manifiesto | `requests` |
| `versiones` | Sí | Versiones a las que aplica el cupo | Rango PEP 440 entre comillas. Para cupos distintos por versión, crear varias reglas con rangos que **no se solapen** | `">=2.31.0"` |
| `max` | Sí | Cupo por severidad | Severidad y cantidad máxima (entero ≥ 0). Las severidades no listadas siguen el umbral global | `{ medium: 4 }` · `{ high: 1, medium: 4 }` |
| `justificacion` | Sí | Por qué se da ese cupo | Texto entre comillas | `"Versiones recientes: se toleran hasta 4 medias mientras se migra."` |

Las excepciones se evalúan **antes** que las reglas. Si varias reglas coinciden con la misma librería y versión, se usa la primera del archivo.

```yaml
reglas_por_paquete:
  - id: REG-001
    paquete: requests
    versiones: ">=2.31.0"
    max: { medium: 4 }
    justificacion: "Versiones recientes: se toleran hasta 4 medias mientras se migra."
  - id: REG-002
    paquete: requests
    versiones: "<2.31.0"
    max: { medium: 2 }
    justificacion: "Versiones antiguas: solo se toleran 2 medias."
```

**Política** (bloque `politica:`): la define el equipo de seguridad y **no se modifica al agregar una excepción**.

| Parámetro | Valor | Efecto |
|---|---|---|
| `max_dias_vigencia` | `90` | Ninguna excepción puede vencer después de hoy + 90 días |
| `aviso_dias_antes` | `15` | El job avisa cuando faltan 15 días o menos para el vencimiento |
| `permitir_excepcion_critical` | `false` | Las vulnerabilidades `critical` nunca se exceptúan: hay que corregirlas |

**Errores frecuentes** (el job falla y muestra el mensaje)

| Mensaje | Causa | Solución |
|---|---|---|
| ``falta `vence` `` (o `id`, `justificacion`, `aprobado_por`) | Falta un campo obligatorio | Agregar el campo |
| ``debe indicar `paquete` y/o `ghsa` `` | La excepción no dice qué cubre | Agregar `paquete`, `ghsa` o ambos |
| ``la política no permite exceptuar vulnerabilidades `critical` `` | Se puso `critical` en `severidades` | Quitarlo y corregir la dependencia |
| ``vence … supera el máximo de 90 días`` | La fecha es demasiado lejana | Usar una fecha dentro de los 90 días |
| ``vence inválido`` | Formato de fecha incorrecto | Usar `AAAA-MM-DD`, por ejemplo `2027-01-31` |
| ``versiones inválido`` | Rango mal escrito (por ejemplo `=>2.0`) | Usar `>=2.0`, `==2.10` o `>=2.0,<3.0` |
| ``id duplicado`` | El `id` ya existe en el archivo | Usar el siguiente correlativo |
| ``max.medium inválido`` | Cantidad negativa o severidad inexistente | Usar `critical`, `high`, `medium` o `low` con un entero ≥ 0 |

---

## Excepciones de código (CodeQL)

Archivo: [`.github/security/excepciones-codigo.yml`](excepciones-codigo.yml) · Job: **Code scanning severidad mínima**

**Paso a paso**

1. **Identificar el hallazgo.** En el PR, abrir el job *Code scanning severidad mínima* → *Summary* → tabla **Detalle**. Ahí están la `Ubicación` (`ruta:línea`), la `Regla de CodeQL` y la `Severidad`.
2. **Intentar corregir primero**: corregir el código, por ejemplo con la sugerencia de Copilot Autofix. La excepción es el último recurso.
3. **Si no se puede corregir**, crear una rama y agregar una entrada en `excepciones-codigo.yml`:
   - bajo `excepciones:` para **aceptar** los hallazgos de una regla en una ruta (con vencimiento), o
   - bajo `reglas_por_ruta:` para darle a una carpeta un **cupo** propio de hallazgos.
4. **Abrir un PR.** El gate valida el archivo: si falta un campo o no cumple la política, el job falla y lista los errores.
5. **Aprobación**: el PR requiere la revisión del code owner de `.github/security/` (CODEOWNERS). Con la aprobación y los checks en verde, se hace merge.
6. **Desde el merge**, el gate deja de contar lo que cubre la excepción: en la tabla **Detalle** aparece como *Exceptuado (`EXC-COD-…`)*.
7. **Antes de que venza** (el job avisa 15 días antes): corregir el código o **renovar** con un nuevo PR que actualice `vence` y `justificacion`. Cuando el hallazgo se corrige, **borrar la entrada**.

No hace falta descartar la alerta en *Security → Code scanning*: el archivo es la única forma de aceptar un hallazgo.

**Parámetros de una excepción** (lista `excepciones:`)

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la excepción en el resumen, en los avisos y en el historial de git | Código único en todo el archivo (no puede repetirse, tampoco con una regla). Convención: `EXC-COD-AAAA-NNN` | `EXC-COD-2026-005` |
| `regla` | Sí | Indica **qué tipo de hallazgo** se acepta | ID de la regla de CodeQL, columna *Regla de CodeQL* del resumen o en la alerta. Distingue mayúsculas. Acepta `*` como comodín | `py/sql-injection` · `actions/code-injection/*` |
| `ruta` | Sí | Indica **en qué código** se acepta | Ruta desde la raíz del repo, sin `/` inicial; columna *Ubicación* sin el número de línea. Distingue mayúsculas. Acepta `*` (que también cruza carpetas). **No puede ser `*`, `**` ni `**/*`** (todo el repo) | `demo/app/app.py` · `demo/legacy/**` |
| `severidades` | No | Limita la excepción a ciertas severidades | Lista con `high`, `medium` y/o `low`. **`critical` no se permite.** Si se omite, aplica a todas excepto `critical` | `[medium, high]` |
| `justificacion` | Sí | Deja registrado por qué se acepta el riesgo | Texto **entre comillas** con el motivo concreto, la mitigación y el plan de corrección | `"El endpoint solo es accesible desde la VPN; se reescribe con consultas parametrizadas en el sprint 24."` |
| `solicitado_por` | No | Trazabilidad: quién pidió la excepción | Usuario de GitHub con `@`, entre comillas | `"@dev-backend"` |
| `aprobado_por` | Sí | Trazabilidad: quién aceptó el riesgo | Usuario del code owner que aprueba el PR, entre comillas. La aprobación efectiva es la revisión del PR | `"@RonnyTabangoBIT"` |
| `vence` | Sí | Hace que la excepción sea **temporal** | Fecha `AAAA-MM-DD` sin comillas, como máximo **hoy + 90 días**. La excepción se aplica hasta ese día incluido | `2027-01-31` |

La excepción se aplica solo si coinciden la `regla`, la `ruta` y, si se indican, las `severidades`. Conviene que la ruta sea **lo más acotada posible**: un archivo concreto mejor que una carpeta.

Ejemplos:

```yaml
excepciones:
  # Una regla en un archivo concreto
  - id: EXC-COD-2026-002
    regla: py/weak-sensitive-data-hashing
    ruta: demo/copilot-autofix/autofix_app.py
    justificacion: "Se deja para probar Copilot Autofix; corrección planificada con pbkdf2."
    solicitado_por: "@RonnyTabangoBIT"
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2026-11-20

  # Una familia de reglas, solo medium/high, en un archivo
  - id: EXC-COD-2026-003
    regla: actions/code-injection/*
    ruta: .github/workflows/advanced-security.yml
    severidades: [medium, high]
    justificacion: "Ejemplo intencional de code injection en workflows para CodeQL."
    aprobado_por: "@RonnyTabangoBIT"
    vence: 2027-01-31
```

**Parámetros de una regla por ruta** (lista `reglas_por_ruta:`)

Una regla no acepta hallazgos concretos: le da a una carpeta un **cupo** propio por severidad, que reemplaza al umbral global (`MAX_*`) para esa carpeta. Sirve, por ejemplo, para código heredado o de demostración que se va a corregir de a poco.

| Parámetro | ¿Obligatorio? | Para qué sirve | Qué colocar | Ejemplo |
|---|---|---|---|---|
| `id` | Sí | Identifica la regla en el resumen | Código único en el archivo. Convención: `REG-COD-NNN` | `REG-COD-003` |
| `ruta` | Sí | Código al que aplica el cupo | Ruta desde la raíz del repo, con comodín | `demo/**` · `legacy/**` |
| `regla` | No | Limita el cupo a ciertas reglas de CodeQL | ID de regla o patrón con `*`. Si se omite, aplica a todas (`*`) | `actions/code-injection/*` |
| `max` | Sí | Cupo por severidad | Severidad y cantidad máxima (entero ≥ 0). Las severidades no listadas siguen el umbral global | `{ critical: 2, high: 5, medium: 3 }` |
| `justificacion` | Sí | Por qué se da ese cupo | Texto entre comillas | `"Código de demostración vulnerable a propósito; no se despliega."` |

Las excepciones se evalúan **antes** que las reglas. Si varias reglas coinciden con el mismo hallazgo, se usa la primera del archivo.

```yaml
reglas_por_ruta:
  - id: REG-COD-001
    ruta: demo/**
    max: { critical: 2, high: 5, medium: 3 }
    justificacion: "Código de demostración vulnerable a propósito; no se despliega."
```

**Política** (bloque `politica:`): igual que en dependencias (90 días de vigencia máxima, aviso 15 días antes y `critical` no exceptuable). La define el equipo de seguridad y **no se modifica al agregar una excepción**.

**Severidad de un hallazgo**: es la que muestra GitHub según el `security-severity` de la regla de CodeQL: **critical** ≥ 9.0, **high** 7.0–8.9, **medium** 4.0–6.9, **low** < 4.0. Aparece en la columna *Severidad* del resumen, junto con el puntaje.

**Errores frecuentes** (el job falla y muestra el mensaje)

| Mensaje | Causa | Solución |
|---|---|---|
| ``falta `ruta` `` (o `id`, `regla`, `justificacion`, `aprobado_por`, `vence`) | Falta un campo obligatorio | Agregar el campo |
| ``ruta demasiado amplia`` | Se usó `*`, `**` o `**/*` | Indicar el archivo o la carpeta concreta |
| ``la política no permite exceptuar hallazgos `critical` `` | Se puso `critical` en `severidades` | Quitarlo y corregir el código |
| ``vence … supera el máximo de 90 días`` | La fecha es demasiado lejana | Usar una fecha dentro de los 90 días |
| ``vence inválido`` | Formato de fecha incorrecto | Usar `AAAA-MM-DD`, por ejemplo `2027-01-31` |
| ``id duplicado`` | El `id` ya existe en el archivo | Usar el siguiente correlativo |
| ``max.high inválido`` | Cantidad negativa o severidad inexistente | Usar `critical`, `high`, `medium` o `low` con un entero ≥ 0 |
| La excepción aparece como *"Vigente, sin coincidencias"* | La `regla` o la `ruta` no coinciden con ningún hallazgo (por ejemplo, mayúsculas distintas o ruta con `/` inicial) | Copiar la regla y la ruta tal como aparecen en la tabla **Detalle** |
