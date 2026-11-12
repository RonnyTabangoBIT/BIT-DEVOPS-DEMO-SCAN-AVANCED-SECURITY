# Dependency Review

El job `dependency-review` del workflow compara el PR contra su rama base y **falla** cuando el PR introduce
(agrega o cambia) una dependencia con severidad `moderate` o superior. Las dependencias que ya existían en la
base y no se modifican no se reportan.

## Estado actual: corregido ✅

| Dependencia | Antes | Ahora | Advisory corregida |
|-------------|-------|-------|--------------------|
| `urllib3` ([`requirements.txt`](requirements.txt)) | `1.26.4` | `2.8.0` | CVE-2021-33503, CVE-2023-43804 y otras |
| `actions/download-artifact` (job `test` del workflow) | `v4.1.2` | `v4.3.0` | CVE-2024-42471 |

Los workflows viven en `.github/` en la raíz, por eso la acción no está en esta carpeta.

## Resultado esperado

- En **Actions → Summary**: “📦 Resumen Dependency Review” con **✅ Sin dependencias vulnerables**.
- En un PR hacia `main`: el check `Dependency Review` en verde.

Para volver a ver el fallo, cambie `urllib3` a `1.26.4` en un PR.
