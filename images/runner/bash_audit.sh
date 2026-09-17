# sourced via BASH_ENV for shells no interactivos de OpenCode/Claude/Codex.
# No es un agente. Solo registra argv en out/.audit/
[[ -n "${AEGIS_AUDIT_DISABLE:-}" ]] && return 0
[[ -z "${AEGIS_AUDIT_LOG:-}" ]] && return 0

# El trap DEBUG salta en CADA comando simple (incluidos bucles y scripts que
# escribe el agente). Lanzar python/date por comando disparaba la latencia:
# un bucle de 500 curls = 1500 arranques de intérprete solo para auditar.
# Todo en bash puro, sin subprocesos: escape JSON con expansión de parámetros
# y timestamp con el builtin printf '%()T'.
_aegis_json() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//[$'\x00'-$'\x1f']/}  # resto de bytes de control: JSON inválido si no se quitan
  _AEGIS_J="\"$s\""
}

_aegis_audit() {
  local cmd=${BASH_COMMAND:-}
  case "$cmd" in
    ""|_aegis_audit*|_aegis_json*|return*|trap*) return 0 ;;
  esac
  local ts argv cwd
  printf -v ts '%(%Y-%m-%dT%H:%M:%SZ)T' -1
  _aegis_json "$cmd"; argv=$_AEGIS_J
  _aegis_json "$PWD"; cwd=$_AEGIS_J
  printf '{"ts":"%s","argv":%s,"cwd":%s}\n' "$ts" "$argv" "$cwd" >>"$AEGIS_AUDIT_LOG" 2>/dev/null || true
}

# Directorio del log una sola vez, no en cada comando.
mkdir -p "$(dirname "$AEGIS_AUDIT_LOG")" 2>/dev/null || true

trap '_aegis_audit' DEBUG
