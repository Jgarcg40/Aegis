#!/usr/bin/env bash
# Quita Aegis de este host: UI, leftover, unidad, imagen runner y el árbol.
# No toca Docker Engine ni OpenCode / Claude Code / Codex.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${AEGIS_IMAGE:-aegis-runner:latest}"
SLIM="${AEGIS_SLIM:-aegis-runner:slim}"

have() { command -v "$1" >/dev/null 2>&1; }

docker_cmd() {
  if have docker && docker info >/dev/null 2>&1; then
    docker "$@"
    return $?
  fi
  if have sg && id -nG "${USER:-$(id -un)}" 2>/dev/null | grep -qw docker; then
    sg docker -c "$(printf '%q ' docker "$@")"
    return $?
  fi
  return 1
}

stop_web() {
  if have systemctl; then
    systemctl --user stop aegis-web.service 2>/dev/null || true
    systemctl --user disable aegis-web.service 2>/dev/null || true
    systemctl --user reset-failed aegis-web.service 2>/dev/null || true
  fi
  if [[ -n "$ROOT" ]]; then
    pkill -f "${ROOT}/aegis-web" 2>/dev/null || true
  fi
  pkill -f '/aegis-web --host' 2>/dev/null || true
  sleep 0.4
  if [[ -n "$ROOT" ]]; then
    pkill -9 -f "${ROOT}/aegis-web" 2>/dev/null || true
  fi
  pkill -9 -f '/aegis-web --host' 2>/dev/null || true
}

strip_path_snippet() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  python3 - "$f" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
try:
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
except OSError:
    raise SystemExit(0)
out = []
skip_next = False
for line in lines:
    if skip_next:
        skip_next = False
        if "opencode/bin" in line and ".local/bin" in line:
            continue
    if line.strip() == "# Aegis — CLIs del host":
        skip_next = True
        continue
    out.append(line)
p.write_text("".join(out), encoding="utf-8")
PY
}

rm_runner() {
  local id
  while read -r id; do
    [[ -n "$id" ]] || continue
    docker_cmd rm -f "$id" >/dev/null 2>&1 || true
  done < <(docker_cmd ps -aq --filter "ancestor=${IMAGE}" 2>/dev/null; docker_cmd ps -aq --filter "ancestor=${SLIM}" 2>/dev/null)
  while read -r id; do
    [[ -n "$id" ]] || continue
    docker_cmd rmi -f "$id" >/dev/null 2>&1 || true
  done < <(docker_cmd images -q "${IMAGE}" 2>/dev/null; docker_cmd images -q "${SLIM}" 2>/dev/null)
}

printf 'Aegis: desinstalando %s\n' "$ROOT"
stop_web
rm -f "${HOME}/.config/systemd/user/aegis-web.service"
rm -f "${HOME}/.config/systemd/user/default.target.wants/aegis-web.service"
if have systemctl; then
  systemctl --user daemon-reload 2>/dev/null || true
fi
strip_path_snippet "${HOME}/.profile"
strip_path_snippet "${HOME}/.bashrc"
rm_runner
rm -rf /tmp/aegis-* /tmp/aegis-cm-*
rm -f /tmp/aegis-ssh-ask /tmp/aegis-pip.log /tmp/aegis-npm-codex.log
cd /
if [[ -n "$ROOT" && "$ROOT" != "/" && -d "$ROOT" ]]; then
  rm -rf "$ROOT"
fi
printf 'Aegis: listo. Docker Engine y los CLI del host siguen.\n'
