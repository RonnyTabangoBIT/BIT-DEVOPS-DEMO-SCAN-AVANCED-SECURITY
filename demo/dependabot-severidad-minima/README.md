# Dependabot – control de severidad mínima

Demuestra cómo actuar **solo** sobre vulnerabilidades de dependencias que alcanzan una severidad mínima
(umbral por defecto: `high`) y tratar el resto como ruido controlado.

[`requirements.txt`](requirements.txt) mezcla severidades:

| Paquete | Severidad máxima | ¿Supera `high`? |
|---------|------------------|-----------------|
| `pyyaml==5.3` | critical | ✅ |
| `jinja2==2.10` | high (+ varias moderate) | ✅ |
| `requests==2.31.0` | moderate | ❌ |

## Piezas del control

1. **`.github/dependabot.yml`** – entrada dedicada a este directorio con `open-pull-requests-limit: 0`
   (sin PRs de versión, solo de seguridad) y el grupo `security-minimum-severity` (`applies-to: security-updates`)
   para agrupar las correcciones en un único PR.
2. **Reglas de auto-triage de Dependabot** (configuración manual, ver abajo): descartan/posponen
   automáticamente las alertas `low`/`medium` y abren PR solo para `high`/`critical`.
3. **Job `dependabot-severity-gate`** en el workflow: consulta las alertas abiertas de este directorio y
   **falla** si hay alguna con severidad `>= MIN_SEVERITY` (`low | medium | high | critical`, editable en el workflow).
   Publica una tabla en **Actions → Summary**.

## Resultado esperado

- **Security → Dependabot**: alertas de `pyyaml` y `jinja2` abiertas; las de `requests` descartadas por la regla.
- **Pull requests**: un PR agrupado de Dependabot para `pyyaml`/`jinja2`.
- **Actions**: `Dependabot severidad mínima` en rojo hasta que se mergee el PR de Dependabot.
  Cambiar `MIN_SEVERITY` a `critical` deja solo `pyyaml` como bloqueante.
