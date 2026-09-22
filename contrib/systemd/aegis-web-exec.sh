#!/usr/bin/env bash
# La UI habla con Docker. Si systemd --user nació antes del usermod
# (linger), el proceso no tiene el grupo docker y el doctor marca
# «imagen falta» aunque aegis-runner:latest exista. sg lee /etc/group.
set -u
export PATH="${HOME}/.opencode/bin:${HOME}/.local/bin:${HOME}/.npm-global/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)" 2>/dev/null || ROOT=""
if [[ -n "$ROOT" && -d "$ROOT" ]]; then
  cd "$ROOT" || cd "${HOME:-/tmp}"
else
  cd "${HOME:-/tmp}" || true
fi
export PWD="$PWD"
web="${ROOT:+$ROOT/aegis-web}"
if [[ -n "$web" && -f "$web" ]]; then
  me=$$
  while read -r p; do
    [[ -z "$p" || "$p" == "$me" || "$p" == "${PPID:-}" ]] && continue
    if tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -Fq -- "$web"; then
      kill "$p" 2>/dev/null || true
    fi
  done < <(pgrep -f "$web" 2>/dev/null || true)
fi
if [[ $# -lt 1 ]]; then
  echo "uso: aegis-web-exec.sh <comando> [args…]" >&2
  exit 2
fi
if ! command -v sg >/dev/null 2>&1; then
  exec "$@"
fi
user="${USER:-$(id -un)}"
in_db=0
in_proc=0
id -nG "$user" 2>/dev/null | grep -qw docker && in_db=1
id -nG 2>/dev/null | grep -qw docker && in_proc=1
if (( in_db == 1 && in_proc == 0 )); then
  quoted=()
  for a in "$@"; do
    quoted+=("$(printf '%q' "$a")")
  done
  exec sg docker -c "exec ${quoted[*]}"
fi
exec "$@"
