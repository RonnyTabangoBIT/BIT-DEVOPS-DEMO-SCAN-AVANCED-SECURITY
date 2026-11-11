# Demos de GitHub Advanced Security

Ejemplos **intencionalmente vulnerables** para probar GitHub Advanced Security con GitHub Actions.

> ⚠️ No desplegar. El código contiene vulnerabilidades a propósito.

## Ejemplos

| Carpeta | Qué demuestra | Job del workflow |
|---------|---------------|------------------|
| [`codeql-code-scanning/`](codeql-code-scanning/) | Code scanning con CodeQL (SQLi, command injection, XSS, path traversal, debug, code injection en Actions) | `test`, `codeql` |
| [`dependency-review/`](dependency-review/) | Bloqueo de dependencias vulnerables en push/PR (`urllib3==1.26.4`, `actions/download-artifact@v4.1.2`) | `dependency-review` |
| [`copilot-autofix/`](copilot-autofix/) | Parches sugeridos por Copilot Autofix sobre alertas de CodeQL en PRs (incluye `errores/`) | `test`, `codeql` |
| [`dependabot-severidad-minima/`](dependabot-severidad-minima/) | Falla cuando las vulnerabilidades de una severidad superan las permitidas (`MAX_CRITICAL`, `MAX_HIGH`, ...; casos en `errores/`) | `dependabot-severity-gate` |

El workflow [`advanced-security.yml`](../.github/workflows/advanced-security.yml) y
[`dependabot.yml`](../.github/dependabot.yml) permanecen en `.github/` en la raíz porque GitHub solo los lee desde ahí.
El workflow se ejecuta en **push a `main`** y en **pull requests hacia `main`**.

## Ajustes manuales requeridos en GitHub

Estos ajustes no se pueden versionar en el repositorio y deben hacerse desde la UI:

1. **Settings → Advanced Security (Code security)**
   - Habilitar *Dependency graph*, *Dependabot alerts* y *Dependabot security updates*.
   - Habilitar *Secret scanning* y *Push protection*.
   - *Code scanning*: usar la configuración **avanzada** (el workflow); si *Default setup* está activo,
     desactivarlo, porque entra en conflicto con el job `codeql`.
   - Verificar que **Copilot Autofix** esté habilitado (Code scanning → *Copilot Autofix*: On).
   - En repos privados se requiere licencia de **GitHub Code Security** (Advanced Security).
2. **Reglas de auto-triage de Dependabot** (Settings → Advanced Security → Dependabot rules → *New rule*):
   - Regla “Ignorar bajo umbral”: *Severity* = `low`, `medium`; *Manifest* = archivos de `demo/dependabot-severidad-minima/`;
     acción **Dismiss alerts** (o *Snooze until patch*).
   - Regla “Corregir sobre umbral”: *Severity* = `high`, `critical`; acción **Open a pull request**.
3. **(Opcional) Branch protection / ruleset sobre `main`** (Settings → Rules → Rulesets): exigir los checks
   `Dependency Review`, `CodeQL (python)` y `Dependabot severidad mínima`, y la regla *Require code scanning results*,
   para que los PRs no se puedan mergear con vulnerabilidades sobre el umbral.

## Flujo de prueba

1. Aplicar los ajustes manuales anteriores.
2. Abrir un PR de esta rama hacia `main` (o hacer push a `main`).
3. En **Actions → Summary** cada job publica su resumen (tests, alertas CodeQL, dependencias vulnerables y gate de severidad).
4. En el PR: comentarios de **Copilot Autofix** sobre `demo/copilot-autofix/autofix_app.py`, y el check `Dependency Review` en rojo.
5. En **Security → Code scanning** y **Security → Dependabot** ver las alertas; Dependabot abre el PR agrupado
   solo para las vulnerabilidades `high`/`critical` de `dependabot-severidad-minima`.
