# Dependabot – control de severidad mínima

Demuestra cómo actuar **solo** sobre vulnerabilidades de dependencias que alcanzan una severidad mínima
(umbral por defecto: `high`) y tratar el resto como ruido controlado.

Este ejemplo usa dos manifiestos de pip reconocidos por Dependabot:

- [`requirements.txt`](requirements.txt) mezcla severidades:

| Paquete | Severidad máxima | ¿Supera `high`? |
|---------|------------------|-----------------|
| `pyyaml==5.3` | critical | ✅ |
| `jinja2==2.10` | high (+ varias moderate) | ✅ |
| `requests==2.31.0` | moderate | ❌ |
- [`Pipfile`](Pipfile) incluye `urllib3==1.26.4` como caso de prueba para CVE-2021-33503.

## Piezas del control

1. **`.github/dependabot.yml`** – entrada dedicada a este directorio con `open-pull-requests-limit: 0`
   (sin PRs de versión, solo de seguridad) y el grupo `security-minimum-severity` (`applies-to: security-updates`)
   para agrupar las correcciones en un único PR.
2. **Reglas de auto-triage de Dependabot** (configuración manual, ver abajo): descartan/posponen
   automáticamente las alertas `low`/`medium` y abren PR solo para `high`/`critical`.
3. **Job `dependabot-severity-gate`** en el workflow: consulta las alertas abiertas de los manifiestos de este directorio y
   **falla** si hay alguna con severidad `>= MIN_SEVERITY` (`low | medium | high | critical`, editable en el workflow).
   Publica en **Actions → Summary** el total de alertas abiertas en el repositorio y en los manifiestos, el total
   por encima/debajo del umbral, y el detalle por paquete. Si no encuentra alertas, lo indica como “no evaluado”
   (no como éxito) y muestra los manifiestos con alertas para ayudar a diagnosticar la ruta.

Dependabot genera alertas a partir de las dependencias detectadas en la **rama predeterminada**. Por eso,
al probarlo desde una rama de características es posible que el job aún no vea este manifiesto: debe llegar
a la rama predeterminada y **Dependency graph** y **Dependabot alerts** deben estar habilitados.

## Resultado esperado

- Una vez que el manifiesto esté en la rama predeterminada y el grafo se haya actualizado, **Security → Dependabot**
  debe mostrar alertas de `pyyaml` y `jinja2`; las de `requests` se descartan con la regla de auto-triage.
- **Pull requests**: un PR agrupado de Dependabot para `pyyaml`/`jinja2`.
- **Actions**: `Dependabot severidad mínima` en rojo hasta que se mergee el PR de Dependabot.
  Cambiar `MIN_SEVERITY` a `critical` deja solo `pyyaml` como bloqueante.
