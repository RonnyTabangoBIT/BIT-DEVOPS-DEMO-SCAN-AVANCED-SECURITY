# Dependabot – umbral de vulnerabilidades por severidad

Demuestra cómo definir **cuántas vulnerabilidades se permiten por severidad** (críticas, altas, medias, bajas)
y **fallar el pipeline cuando alguna severidad supera su umbral**.

## Estado actual: vulnerable, pero dentro del umbral ✅

| Manifiesto | Paquete | Vulnerabilidades |
|------------|---------|------------------|
| [`requirements.txt`](requirements.txt) | `jinja2==2.10` | 1 high + 5 medium |
| [`requirements.txt`](requirements.txt) | `requests==2.31.0` | 3 medium |

## Piezas del control

1. **Job `dependabot-severity-gate`** ([`severity_gate.py`](../../.github/scripts/severity_gate.py)): lee los
   `requirements*.txt` y `Pipfile` del directorio (recursivo), los evalúa contra la **GitHub Advisory Database**
   (la misma fuente que usa Dependabot) y **falla** si en alguna severidad las vulnerabilidades encontradas
   superan las permitidas. Los umbrales se editan en el workflow:

   | Variable | Valor en el workflow | Significado |
   |----------|---------------------:|-------------|
   | `MAX_CRITICAL` | `0` | Vulnerabilidades críticas permitidas |
   | `MAX_HIGH` | `2` | Vulnerabilidades altas permitidas |
   | `MAX_MEDIUM` | `15` | Vulnerabilidades medias permitidas |
   | `MAX_LOW` | `-1` | Vulnerabilidades bajas permitidas (vacío o `-1` = sin límite) |

   En **Actions → Summary** publica, por severidad, las **encontradas**, las **permitidas**, el **exceso** y el
   estado, además del total y el detalle por paquete. Deja anotaciones `::error` sobre la línea del manifiesto.
   Funciona en cualquier rama o PR y solo usa `GITHUB_TOKEN`.
2. **`.github/dependabot.yml`** – entrada dedicada a este directorio con `open-pull-requests-limit: 0`
   (sin PRs de versión, solo de seguridad) y el grupo `security-minimum-severity` para agrupar las correcciones.
3. **Reglas de auto-triage de Dependabot** (configuración manual, ver [`demo/README.md`](../README.md)).

## Resultado esperado

| Severidad | Encontradas | Permitidas | Exceso | Estado |
|---|---:|---:|---:|---|
| Críticas (critical) | 0 | 0 | 0 | ✅ Dentro del umbral |
| Altas (high) | 1 | 2 | 0 | ✅ Dentro del umbral |
| Medias (medium) | 8 | 15 | 0 | ✅ Dentro del umbral |
| Bajas (low) | 0 | sin límite | 0 | ✅ Dentro del umbral |
| **Total** | **9** | | | ✅ |

**Para ver el fallo**, agregue por ejemplo `pyyaml==5.3` (2 critical) o `urllib3==1.26.4` (8 high) a
`requirements.txt`: el job falla porque supera `MAX_CRITICAL=0` o `MAX_HIGH=2`.

> Los conteos dependen de la Advisory Database al momento de ejecutar y pueden crecer con nuevas advisories.

### Probar en local

```bash
pip install packaging
MAX_CRITICAL=0 MAX_HIGH=2 MAX_MEDIUM=15 python .github/scripts/severity_gate.py   # desde la raíz; exit 1 si se supera
```
