# Demos de GitHub Advanced Security

Ejemplos **intencionalmente vulnerables** para probar GitHub Advanced Security con GitHub Actions.

> ⚠️ No desplegar. El código contiene vulnerabilidades a propósito.

## Ejemplos

| Carpeta | Qué demuestra | Job del workflow |
|---------|---------------|------------------|
| [`codeql-code-scanning/`](codeql-code-scanning/) | Code scanning con CodeQL (SQLi, command injection, XSS, path traversal, debug, code injection en Actions) | `test`, `codeql` |
| [`dependency-review/`](dependency-review/) | Bloqueo de dependencias vulnerables en push/PR (corregido: `urllib3==2.8.0`, `actions/download-artifact@v4.3.0`) | `dependency-review` |
| [`copilot-autofix/`](copilot-autofix/) | Parches sugeridos por Copilot Autofix sobre alertas de CodeQL en PRs | `test`, `codeql` |
| [`dependabot-severidad-minima/`](dependabot-severidad-minima/) | Falla cuando las vulnerabilidades de una severidad superan las permitidas (`MAX_CRITICAL`, `MAX_HIGH`, ...), con excepciones y reglas por versión en `.github/security/excepciones.yml` | `dependabot-severity-gate` |

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
3. **Ruleset sobre `main`** (Settings → Rules → Rulesets): exigir los checks `Dependabot severidad mínima`,
   `Dependency Review`, `CodeQL (python)`, `CodeQL (actions)`, `Tests (codeql-code-scanning)` y `Tests (copilot-autofix)`,
   la regla *Require code scanning results*, **1 aprobación** y ☑ **Require review from Code Owners**.
4. **Aprobación desde Actions** (Settings → Actions → General → Workflow permissions):
   ☑ *Allow GitHub Actions to create and approve pull requests*, para el job `Aprobación automática`.

5. **(Opcional) Secreto `SECURITY_AUDIT_TOKEN`** (Settings → Secrets and variables → Actions): fine-grained PAT con
   *Secret scanning alerts: Read-only*, para que la **Auditoría de excepciones** incluya secret scanning.

## Workflows adicionales

| Workflow | Disparo | Qué hace |
|---|---|---|
| [`autofix-agent.yml`](../.github/workflows/autofix-agent.yml) | Manual (`workflow_dispatch`) | Verifica los requisitos de Copilot Autofix, genera autofix por API para las alertas de CodeQL de `main` y, opcionalmente, abre un PR de remediación |
| [`security-exceptions-audit.yml`](../.github/workflows/security-exceptions-audit.yml) | Lunes, manual o al cambiar la política | Valida los descartes de code scanning y secret scanning contra [`politica-descartes.yml`](../.github/security/politica-descartes.yml) y publica un registro CSV |

Ambos necesitan estar en `main` para poder ejecutarse manualmente. Ver las secciones 4.7 a 4.9 y 5 de
[`INVESTIGACION-ADVANCED-SECURITY.md`](../INVESTIGACION-ADVANCED-SECURITY.md).

## Aprobadores (CODEOWNERS)

[`.github/CODEOWNERS`](../.github/CODEOWNERS) define el aprobador de cada ruta. Al abrir un PR, GitHub lo asigna
automáticamente como reviewer y, con *Require review from Code Owners*, el merge muestra
*"Waiting on code owner review from @…"* hasta que apruebe.

- `.github/security/excepciones.yml` (control de excepciones) y `.github/` (workflow y umbrales `MAX_*`) están
  protegidos: nadie puede aceptar una vulnerabilidad o subir un umbral sin la aprobación del code owner.
- El job `Aprobación automática` aprueba el PR (como `github-actions[bot]`) cuando todos los checks pasan y el autor
  está en `APROBADORES`. Esa aprobación cubre *Required approvals*, pero **no** la de code owner: un bot no puede ser code owner.
- GitHub no permite que el autor apruebe su propio PR. En esta demo, con un único code owner que además es el autor,
  el PR queda en *"Review required"*: es el comportamiento esperado y sirve para ver el mensaje del aprobador.
  En un equipo real, el code owner es otra persona o un team de la organización.

## Flujo de prueba

1. Aplicar los ajustes manuales anteriores.
2. Abrir un PR de esta rama hacia `main` (o hacer push a `main`).
3. En **Actions → Summary** cada job publica su resumen (tests, alertas CodeQL, dependencias vulnerables y gate de
   severidad con las tablas de umbral global, reglas por paquete y control de excepciones).
4. En el PR: el code owner aparece como reviewer requerido y `github-actions` deja la aprobación automática.
5. En **Security → Code scanning** y **Security → Dependabot** ver las alertas.
