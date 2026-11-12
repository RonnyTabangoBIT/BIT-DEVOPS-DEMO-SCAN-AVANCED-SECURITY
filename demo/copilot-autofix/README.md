# Copilot Autofix (code scanning)

[`autofix_app.py`](autofix_app.py) contiene vulnerabilidades que CodeQL detecta y para las que
**Copilot Autofix** genera un parche sugerido.

| Ruta | Regla CodeQL | Corrección esperada de Autofix |
|------|--------------|--------------------------------|
| `POST /profile` | `py/unsafe-deserialization` (`pickle.loads`) | Usar `json.loads` |
| `POST /register` | `py/weak-sensitive-data-hashing` (`md5`) | KDF con salt (`hashlib.pbkdf2_hmac`, argon2, etc.) |
| `GET /login` | `py/url-redirection` | Validar que `next` sea relativa / del mismo host |

> Los errores adicionales para probar Autofix (carpeta `errores/`: SQL injection, command injection,
> path traversal, XSS y stack trace) se prueban en un PR dedicado desde la rama
> `feature/demo-app-advanced-security`, para no bloquear el merge de otros cambios con la regla
> *Require code scanning results*.

> Autofix solo comenta en el PR las alertas **nuevas** en líneas modificadas por ese PR. Si un archivo ya está
> en `main` con la alerta, use la Opción B (desde la alerta) o modifique la línea vulnerable en el PR.

## Cómo probarlo

### Opción A – en un Pull Request (recomendado)
1. Mergear esta rama a `main` para que exista el análisis base (o abrir el PR directamente: el workflow
   ya se ejecuta en `pull_request` hacia `main`).
2. Abrir un PR hacia `main` que modifique `autofix_app.py` (p. ej. esta misma rama, o un cambio menor en el archivo).
3. Cuando termine el job `CodeQL (python)`, Copilot Autofix publica comentarios en la pestaña
   **Files changed** con el parche sugerido.
4. Revisar y pulsar **Commit suggestion**; el siguiente análisis cierra la alerta.

### Opción B – desde una alerta existente
1. **Security → Code scanning** → abrir una alerta de `autofix_app.py`.
2. Pulsar **Generate fix** → revisar el parche → **Create PR with fix**.

## Tests

```bash
cd demo/copilot-autofix
pip install -r requirements.txt pytest
python -m pytest
```

Los tests usan entradas benignas, por lo que deben seguir pasando después de aplicar los parches de Autofix
(el job `test` del workflow los ejecuta como validación del fix).
