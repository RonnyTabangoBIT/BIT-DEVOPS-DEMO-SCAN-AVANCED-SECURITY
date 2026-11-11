# Dependabot – control de severidad mínima

Demuestra cómo actuar **solo** sobre vulnerabilidades de dependencias que alcanzan una severidad mínima
y **fallar el pipeline cuando se supera el umbral de vulnerabilidades permitidas**.

## Estructura

| Manifiesto | Paquete | Severidad máxima | ¿Bloquea con `MIN_SEVERITY=high`? |
|------------|---------|------------------|-----------------------------------|
| [`requirements.txt`](requirements.txt) (base) | `requests==2.31.0` | medium | ➖ Permitida |
| [`errores/requirements.txt`](errores/requirements.txt) | `pyyaml==5.3` | critical | ❌ |
| [`errores/requirements.txt`](errores/requirements.txt) | `jinja2==2.10` | high (+ varias medium) | ❌ |
| [`errores/Pipfile`](errores/Pipfile) | `urllib3==1.26.4` | high (+ varias medium) | ❌ |

- La **base** solo tiene vulnerabilidades bajo la severidad mínima → el gate pasa ✅.
- La carpeta **`errores/`** agrega vulnerabilidades `high`/`critical` → se supera el umbral y el gate falla ❌.

## Piezas del control

1. **Job `dependabot-severity-gate`** ([`severity_gate.py`](../../.github/scripts/severity_gate.py)): lee los
   `requirements*.txt` y `Pipfile` del directorio (recursivo), los evalúa contra la **GitHub Advisory Database**
   (la misma fuente que usa Dependabot) y **falla** si las vulnerabilidades con severidad `>= MIN_SEVERITY`
   son más que `MAX_ALLOWED`. Ambos se editan en el workflow:

   | Variable | Valor por defecto | Significado |
   |----------|-------------------|-------------|
   | `MIN_SEVERITY` | `high` | Severidad a partir de la cual una vulnerabilidad es bloqueante (`low \| medium \| high \| critical`) |
   | `MAX_ALLOWED` | `0` | Cantidad de vulnerabilidades bloqueantes permitidas antes de fallar |

   Publica en **Actions → Summary** el total por severidad, cuántas bloquean y el detalle por paquete, y deja
   anotaciones `::error` sobre la línea del manifiesto. Funciona en cualquier rama o PR y solo usa `GITHUB_TOKEN`
   (no necesita que las alertas existan en la rama predeterminada ni un PAT).
2. **`.github/dependabot.yml`** – entrada dedicada a este directorio y a `errores/` con `open-pull-requests-limit: 0`
   (sin PRs de versión, solo de seguridad) y el grupo `security-minimum-severity` para agrupar las correcciones.
3. **Reglas de auto-triage de Dependabot** (configuración manual, ver [`demo/README.md`](../README.md)): descartan
   las alertas `low`/`medium` y abren PR solo para `high`/`critical`.

## Resultado esperado

| Escenario | Bloqueantes (`>= high`) | Resultado del job |
|-----------|------------------------:|-------------------|
| Con `errores/` (estado actual) | 11 (2 critical + 9 high) | ❌ falla: se supera el umbral (`MAX_ALLOWED=0`) |
| Con `MAX_ALLOWED: 11` | 11 | ✅ dentro del umbral |
| Con `MIN_SEVERITY: critical` | 2 | ❌ falla (solo `pyyaml`) |
| Sin la carpeta `errores/` | 0 | ✅ dentro del umbral |

> Los conteos dependen de la Advisory Database al momento de ejecutar y pueden crecer con nuevas advisories.

Además, en **Security → Dependabot** (cuando los manifiestos estén en la rama predeterminada) aparecen las alertas
de `pyyaml`, `jinja2` y `urllib3`, y Dependabot abre un PR agrupado para corregirlas.

### Probar en local

```bash
pip install packaging
python .github/scripts/severity_gate.py          # desde la raíz del repo; exit 1 si se supera el umbral
MAX_ALLOWED=20 python .github/scripts/severity_gate.py
```
