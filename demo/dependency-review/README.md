# Dependency Review

`requirements.txt` incluye `urllib3==1.26.4` (CVE-2021-33503). El job `dependency-review` del workflow
compara el commit/PR contra su base y **falla** cuando se introduce una dependencia con severidad `moderate` o superior.

También detecta la acción vulnerable `actions/download-artifact@v4.1.2` (CVE-2024-42471) usada en el job `test`
del workflow (los workflows deben vivir en `.github/` en la raíz, por eso no está en esta carpeta).

## Resultado esperado

- En **Actions → Summary**: tabla “📦 Resumen Dependency Review” con las dependencias vulnerables.
- En un PR hacia `main`: el check `Dependency Review` en rojo.
- En **Security → Dependabot**: las alertas correspondientes.
