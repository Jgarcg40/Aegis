#!/usr/bin/env bash
# Aegis · instalador on-premise
# Clona / descomprime el proyecto, ejecuta esto, y deja el host listo.
# Las suscripciones (Grok, ChatGPT, Claude) se activan después en la UI.
set -u
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

IMAGE="${AEGIS_IMAGE:-aegis-runner:latest}"
SLIM="${AEGIS_SLIM:-aegis-runner:slim}"
WEB_HOST="${AEGIS_WEB_HOST:-0.0.0.0}"
WEB_PORT="${AEGIS_WEB_PORT:-8787}"
MIN_PY="3.12"
IMAGE_FREE_GB=45

DO_CHECK=0
DO_PACK=0
DO_WIPE=0
WIPE_CLIS=0
PACK_OUT=""
SKIP_IMAGE=0
SKIP_WEB=0
DO_SLIM=0
IMAGE_ONLY=0
ASSUME_YES=0

BLOCKED=()   # no se puede seguir sin esto
MISSING=()   # se puede vivir, pero hay que instalarlo a mano
DONE=()

_tty=0
[[ -t 1 ]] && _tty=1
if [[ "${NO_COLOR:-}" == "1" ]]; then _tty=0; fi

if (( _tty )); then
  C0=$'\033[0m'; CDIM=$'\033[2m'; CB=$'\033[1m'
  CG=$'\033[38;5;114m'; CR=$'\033[38;5;203m'; CY=$'\033[38;5;221m'
  CA=$'\033[38;5;178m'; CBLE=$'\033[38;5;109m'; CW=$'\033[38;5;252m'
else
  C0=""; CDIM=""; CB=""; CG=""; CR=""; CY=""; CA=""; CBLE=""; CW=""
fi

ok()   { printf '  %s✓%s  %s\n' "$CG" "$C0" "$*"; DONE+=("$*"); }
warn() { printf '  %s!%s  %s\n' "$CY" "$C0" "$*"; }
fail() { printf '  %s✗%s  %s\n' "$CR" "$C0" "$*"; }
info() { printf '  %s·%s  %s\n' "$CDIM" "$C0" "$*"; }
note() { printf '     %s%s%s\n' "$CDIM" "$*" "$C0"; }

step() {
  local n="$1"; shift
  printf '\n%s▸ %s%s%s  %s%s\n' "$CA" "$CB" "$n" "$C0" "$CW" "$*$C0"
}

banner() {
  printf '%s\n' "${CA}"
  cat <<'EOF'
        ╭────────────────────────────╮
        │          A E G I S         │
        │   orquestador on-premise   │
        ╰────────────────────────────╯
EOF
  printf '%s' "$C0"
  printf '  %sarnés · sandbox Docker · UI%s\n' "$CDIM" "$C0"
  printf '  %s%s%s\n' "$CDIM" "$ROOT" "$C0"
}

usage() {
  cat <<EOF
Uso: ./install.sh [opciones]

  (sin flags)     instala deps, imagen runner y UI; pregunta por cada CLI
  --check         solo diagnostica; no instala
  --skip-image    no construye la imagen Kali (lenta, ~31 GB)
  --slim          también construye aegis-runner:slim (pruebas --smoke)
  --image-only    solo la imagen (hace falta Docker ya listo)
  --skip-web      no instala ni arranca el servicio de la UI
  --pack [ZIP]    empaqueta una copia limpia (sin data/, resultados de evals, runs ni logs)
  --wipe          para la UI (también el python huérfano), quita la unidad systemd
  --wipe-clis     con --wipe: también OpenCode, Claude Code, Codex y sus homes
  ./uninstall.sh  Aegis entero (UI, leftover, imagen runner, árbol). Docker y CLI no.
  -y, --yes       no pregunta; instala también OpenCode, Claude Code y Codex
  -h, --help      esta ayuda

OpenCode, Claude Code y Codex son opcionales: se pregunta uno a uno
(Enter = no). Si los instalas luego a mano, la UI los detecta al
refrescar Modelos. Las suscripciones se activan ahí; este script
no abre logins.

Sudo: pregunta en la terminal y luego la contraseña UNA vez, solo
si hace falta: Docker Engine, grupo docker, linger (UI al reiniciar),
curl / Python 3.12.
systemctl --user de la UI no usa sudo.

Bind de la UI (también en la unidad systemd):
  AEGIS_WEB_HOST   (defecto 0.0.0.0)
  AEGIS_WEB_PORT   (defecto 8787)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) DO_CHECK=1 ;;
    --skip-image) SKIP_IMAGE=1 ;;
    --skip-web) SKIP_WEB=1 ;;
    --slim) DO_SLIM=1 ;;
    --image-only) IMAGE_ONLY=1 ;;
    --pack)
      DO_PACK=1
      if [[ "${2:-}" != "" && "${2:-}" != -* ]]; then PACK_OUT="$2"; shift; fi
      ;;
    --wipe) DO_WIPE=1 ;;
    --wipe-clis) WIPE_CLIS=1; DO_WIPE=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '%sflag desconocido: %s%s\n' "$CR" "$1" "$C0"; usage; exit 2 ;;
  esac
  shift
done

have() { command -v "$1" >/dev/null 2>&1; }
sudo_n() { have sudo && sudo -n true >/dev/null 2>&1; }

SUDO_OK=0
SUDO_ASKED=0
SUDO_DENIED=0
USE_SUDO_DOCKER=0
ADDED_DOCKER_GROUP=0

valid_web_bind() {
  # host/puerto van a ExecStart: nada de espacios ni $ ; |
  if [[ -z "$WEB_HOST" || "$WEB_HOST" == *[[:space:]/\\\'\"\`\$\;\|\&\<\>]* ]]; then
    fail "AEGIS_WEB_HOST inválido: $WEB_HOST"
    return 1
  fi
  if [[ ! "$WEB_PORT" =~ ^[0-9]+$ ]] || (( WEB_PORT < 1 || WEB_PORT > 65535 )); then
    fail "AEGIS_WEB_PORT inválido: $WEB_PORT"
    return 1
  fi
  return 0
}

ask_permission() {
  local q="$1"
  if (( ASSUME_YES )); then return 0; fi
  if [[ ! -t 0 ]]; then
    fail "no hay terminal para confirmar. Relanza sin tubería, o pasa -y"
    return 1
  fi
  local a
  printf '  %s?%s  %s [S/n] ' "$CA" "$C0" "$q"
  read -r a || true
  [[ -z "$a" || "$a" == [sSyY]* ]]
}

# Pregunta ANTES de tocar el sistema. Luego, si hace falta, sudo -v (contraseña).
# Si dice que no, SUDO_DENIED se queda: no insistas.
need_root() {
  local what="$1"
  if (( SUDO_OK )); then return 0; fi
  if (( SUDO_DENIED )); then
    fail "sin tu permiso no toco el sistema"
    return 1
  fi
  if (( ! SUDO_ASKED )); then
    printf '\n  %sPermiso de administrador%s\n' "$CB$CA" "$C0"
    printf '  Voy a usar sudo para:\n'
    printf '    · %s\n' "$what"
    printf '    · si faltan: Docker Engine, grupo docker, linger, curl / Python 3.12\n'
    if ! ask_permission "¿Me das permiso para usar sudo?"; then
      SUDO_DENIED=1
      fail "sin tu permiso no toco el sistema"
      return 1
    fi
    SUDO_ASKED=1
  fi
  if (( SUDO_OK )) || sudo_n; then SUDO_OK=1; return 0; fi
  if ! have sudo; then
    fail "no hay comando sudo en este host"
    return 1
  fi
  if [[ ! -t 0 ]] && (( ! ASSUME_YES )); then return 1; fi
  info "contraseña de sudo (una vez en esta sesión)"
  if sudo -v; then SUDO_OK=1; return 0; fi
  return 1
}

ensure_sudo() { need_root "operación de administrador"; }

sudo_do() {
  ensure_sudo || return 1
  sudo -n "$@"
}

# Tras usermod -aG docker, esta sesión aún no tiene el grupo:
# construimos la imagen con sudo docker y avisamos de re-login.
as_docker() {
  if command docker info >/dev/null 2>&1; then
    command docker "$@"
    return $?
  fi
  if (( USE_SUDO_DOCKER )); then
    sudo_do docker "$@"
    return $?
  fi
  command docker "$@"
}

docker_talks() {
  command docker info >/dev/null 2>&1 && return 0
  if (( USE_SUDO_DOCKER )); then
    sudo -n docker info >/dev/null 2>&1 && return 0
  fi
  return 1
}

# Wipe/reinstall de Docker deja manifests en containerd sin el blob.
repair_docker_base() {
  local base="kalilinux/kali-rolling"
  info "quito $base a medias y la vuelvo a bajar"
  if (( SUDO_OK )) || sudo_n; then
    sudo_do systemctl restart containerd.service 2>/dev/null || true
    sudo_do systemctl restart docker.service 2>/dev/null || true
    sleep 2
  fi
  as_docker rmi -f "$base" >/dev/null 2>&1 || true
  as_docker pull "$base"
}

py_ok() {
  "$1" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)" 2>/dev/null
}

pick_python() {
  local c
  for c in python3.13 python3.12 python3; do
    if have "$c" && py_ok "$c"; then
      printf '%s' "$(command -v "$c")"
      return 0
    fi
  done
  return 1
}

ver_of() {
  local b="$1"
  if have "$b"; then "$b" --version 2>/dev/null | head -1 | tr -d '\r'; else echo ""; fi
}

free_gb() {
  df -P "$ROOT" 2>/dev/null | awk 'NR==2{printf "%d", $4/1024/1024}'
}

in_docker_group() {
  # Sesión actual (tras usermod sigue sin el grupo hasta re-login).
  id -nG 2>/dev/null | grep -qw docker
}

_user_in_docker_db() {
  # /etc/group, no los grupos de esta shell.
  id -nG "$USER" 2>/dev/null | grep -qw docker
}

append_path_line() {
  local file="$1" line="$2"
  [[ -f "$file" ]] || touch "$file"
  if grep -Fqs "$line" "$file" 2>/dev/null; then
    return 0
  fi
  printf '\n# Aegis — CLIs del host\n%s\n' "$line" >>"$file"
}

ensure_path() {
  export PATH="$HOME/.opencode/bin:$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"
  # --check: no toques .profile
  if (( DO_CHECK )); then
    return 0
  fi
  local extra='$HOME/.opencode/bin:$HOME/.local/bin:$HOME/.npm-global/bin'
  local line="export PATH=\"$extra:\$PATH\""
  append_path_line "$HOME/.profile" "$line"
  if [[ -f "$HOME/.bashrc" ]]; then
    append_path_line "$HOME/.bashrc" "$line"
  fi
}

# curl a un mktemp; no pipes a bash (curl fallido + sh vacío = 0).
# $3 = respuestas (una por línea). Codex pregunta "Start Codex now?" por
# /dev/tty: un pipe no basta y Ctrl+C tumba este install.sh.
run_official_script() {
  local url="$1" interp="${2:-bash}" feed="${3:-}"
  local tmp="" rc=1
  tmp="$(umask 077; mktemp "${TMPDIR:-/tmp}/aegis-dl.XXXXXX")" || return 1
  if curl -fsSL "$url" -o "$tmp"; then
    chmod 700 "$tmp"
    if [[ -n "$feed" ]]; then
      printf '%s\n' "$feed" | CI=1 CODEX_NON_INTERACTIVE=1 "$interp" "$tmp"
    else
      CI=1 CODEX_NON_INTERACTIVE=1 "$interp" "$tmp"
    fi
    rc=$?
  else
    rc=1
  fi
  rm -f "$tmp"
  return "$rc"
}

write_web_unit() {
  local src="$1" dst="$2" root="$3" py="$4" host="$5" port="$6"
  python3 - "$src" "$dst" "$root" "$py" "$host" "$port" <<'PY'
import sys
from pathlib import Path

src, dst, root, py, host, port = sys.argv[1:7]
text = Path(src).read_text(encoding="utf-8")
text = (
    text.replace("{{AEGIS_ROOT}}", root)
    .replace("{{PYTHON}}", py)
    .replace("{{AEGIS_WEB_HOST}}", host)
    .replace("{{AEGIS_WEB_PORT}}", port)
)

def q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

web = str(Path(root) / "aegis-web")
wrapper = str(Path(root) / "contrib" / "systemd" / "aegis-web-exec.sh")
exec_start = f"ExecStart={q(wrapper)} {q(py)} {q(web)} --host {host} --port {port}"
out = []
for line in text.splitlines(keepends=True):
    if line.startswith("ExecStart="):
        nl = "\n" if line.endswith("\n") else ""
        out.append(exec_start + nl)
    else:
        out.append(line)
Path(dst).parent.mkdir(parents=True, exist_ok=True)
Path(dst).write_text("".join(out), encoding="utf-8")
PY
}

confirm() {
  local q="$1"
  if (( ASSUME_YES )); then return 0; fi
  if [[ ! -t 0 ]]; then return 0; fi
  local a
  printf '  %s?%s  %s [S/n] ' "$CA" "$C0" "$q"
  read -r a || true
  [[ -z "$a" || "$a" == [sSyY]* ]]
}

# CLIs opcionales: Enter = no. -y instala los tres. Sin TTY, no se instalan.
ask_optional() {
  local q="$1"
  if (( ASSUME_YES )); then return 0; fi
  if [[ ! -t 0 ]]; then return 1; fi
  local a
  printf '  %s?%s  %s [s/N] ' "$CA" "$C0" "$q"
  read -r a || true
  [[ "$a" == [sSyY]* ]]
}

pack_zip() {
  local dest="${1:-}"
  if [[ -z "$dest" ]]; then
    dest="$(cd "$ROOT/.." && pwd)/aegis-onprem.zip"
  fi
  dest="$(python3 -c "import os,sys; print(os.path.abspath(sys.argv[1]))" "$dest")"
  step "pack" "Copia limpia → $dest"
  PYTHONPATH="$ROOT" python3 - "$ROOT" "$dest" <<'PY'
import os, sys, zipfile
from pathlib import Path

root = Path(sys.argv[1]).resolve()
dest = Path(sys.argv[2]).resolve()
dest.parent.mkdir(parents=True, exist_ok=True)

skip_dir = {
    ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".idea", ".vscode", "node_modules",
    "tests", "evals", "labs",
}
skip_file_suffix = {".pyc", ".pyo", ".log", ".zip"}
skip_names = {".env", "secrets.env", ".live", "queue.json"}

def keep(rel: Path) -> bool:
    parts = rel.parts
    if any(p in skip_dir for p in parts):
        return False
    if rel.name in skip_names:
        return False
    if rel.suffix in skip_file_suffix:
        return False
    # Un solo Markdown en el zip: el README de la raíz.
    if rel.suffix.lower() == ".md":
        return parts == ("README.md",)
    if parts[:1] == ("data",):
        # Nunca runs, logs, colas ni evidencia. Solo el marcador vacío.
        return rel.name == ".gitkeep" and parts == ("data", ".gitkeep")
    return True

count = 0
bytes_ = 0
with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if d not in skip_dir]
        if rel_dir.parts[:1] == ("data",) and rel_dir.parts != ("data",):
            dirnames[:] = []
            continue
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root)
            if not keep(rel):
                continue
            zf.write(path, arcname=str(Path("aegis") / rel))
            count += 1
            bytes_ += path.stat().st_size
    if not any(i.filename == "aegis/data/.gitkeep" for i in zf.infolist()):
        keep_me = zipfile.ZipInfo("aegis/data/.gitkeep")
        keep_me.external_attr = 0o644 << 16
        zf.writestr(keep_me, "# Los runs viven aquí (data/runs/).\n")
        count += 1

print(f"files={count} bytes={bytes_} dest={dest}")
PY
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    fail "no pude escribir el zip"
    return 1
  fi
  local sz
  sz="$(python3 -c "import os; print(f'{os.path.getsize(os.path.abspath(\"$dest\"))/1_048_576:.1f} MB')" 2>/dev/null || echo "?")"
  ok "zip listo · $sz · $dest"
  info "dentro: código, imagen (Dockerfile), instalador, README, capturas"
  info "fuera: tests/, evals/, labs/, data/runs, logs, .venv, .git, __pycache__"
  return 0
}

stop_stale_web() {
  local root="${1:-$ROOT}"
  if have systemctl; then
    systemctl --user stop aegis-web.service 2>/dev/null || true
  fi
  if [[ -n "$root" ]]; then
    pkill -f "${root}/aegis-web" 2>/dev/null || true
  fi
  pkill -f '/aegis-web --host' 2>/dev/null || true
  sleep 0.3
}

wipe_install() {
  step "wipe" "UI y, con --wipe-clis, los tres CLI"
  stop_stale_web "$ROOT"
  if have systemctl; then
    systemctl --user disable --now aegis-web.service 2>/dev/null || true
    systemctl --user reset-failed aegis-web.service 2>/dev/null || true
  fi
  rm -f "$HOME/.config/systemd/user/aegis-web.service"
  if have systemctl; then
    systemctl --user daemon-reload 2>/dev/null || true
  fi
  ok "aegis-web parado"
  if (( WIPE_CLIS )); then
    rm -f "$HOME/.local/bin/codex" "$HOME/.local/bin/claude" \
      "$HOME/.local/bin/codex-code-mode-host" "$HOME/.local/bin/opencode"
    rm -rf "$HOME/.codex" "$HOME/.claude" "$HOME/.local/share/claude" \
      "$HOME/.opencode"
    rm -f "$HOME/.claude.json"
    ok "OpenCode, Claude Code y Codex quitados del host"
  fi
  info "este árbol no se borra (estás dentro): rm -rf \"$ROOT\"  y descomprime el zip"
}

preflight() {
  step "1/8" "Sistema"
  local os k arch
  os="$(uname -s 2>/dev/null || echo ?)"
  k="$(uname -r 2>/dev/null || echo ?)"
  arch="$(uname -m 2>/dev/null || echo ?)"
  if [[ "$os" != "Linux" ]]; then
    fail "este instalador es para Linux (visto: $os)"
    BLOCKED+=("Linux")
  else
    ok "Linux $k · $arch"
  fi
  if [[ "$arch" != "x86_64" && "$arch" != "amd64" ]]; then
    warn "imagen y binarios se prueban en x86_64 (tú: $arch). Puede fallar."
  fi

  local py=""
  if py="$(pick_python)"; then
    ok "Python $($py -c 'import sys; print("%d.%d.%d"%sys.version_info[:3])') · $py"
  else
    fail "hace falta Python $MIN_PY+ — el instalador lo pondrá con apt + sudo"
    if (( DO_CHECK )); then BLOCKED+=("Python $MIN_PY+"); fi
  fi

  if have curl; then ok "curl $(curl --version 2>/dev/null | awk '{print $2; exit}')"
  else
    fail "falta curl — el instalador lo pondrá con apt + sudo"
    if (( DO_CHECK )); then BLOCKED+=("curl"); fi
  fi

  if have docker; then
    ok "Docker $(docker --version 2>/dev/null | sed 's/Docker version //')"
    if docker_talks; then
      ok "daemon Docker responde"
    else
      fail "Docker está instalado pero el daemon no responde (¿servicio parado? ¿sin grupo docker?)"
      note "el instalador lo arranca y te mete en el grupo docker (pide sudo)"
      if (( DO_CHECK )); then BLOCKED+=("Docker daemon / permiso"); fi
    fi
  else
    fail "falta Docker Engine — el instalador lo pondrá con sudo"
    note "sin Docker no hay runs (no hay fallback en el host)"
    if (( DO_CHECK )); then BLOCKED+=("Docker Engine"); fi
  fi

  local gb
  gb="$(free_gb)"
  if [[ -n "$gb" ]]; then
    if (( gb < IMAGE_FREE_GB )) && (( ! SKIP_IMAGE )); then
      warn "disco libre ~${gb} GB — la imagen Kali pesa ~31 GB (pide ≥${IMAGE_FREE_GB} GB libres para el build)"
      note "puedes seguir con --skip-image y construirla luego"
    else
      ok "disco libre ~${gb} GB"
    fi
  fi
}

try_apt_min() {
  have apt-get || return 0
  local pkgs=()
  have curl || pkgs+=(curl ca-certificates)
  if ! pick_python >/dev/null; then
    pkgs+=(python3 python3-pip python3-venv python3-yaml)
  elif ! python3 -c "import yaml" 2>/dev/null; then
    pkgs+=(python3-yaml)
  fi
  (( ${#pkgs[@]} )) || return 0
  step "1a" "Paquetes mínimos (apt): ${pkgs[*]}"
  if ! need_root "apt-get install ${pkgs[*]}"; then
    fail "hace falta sudo para: apt-get install ${pkgs[*]}"
    note "sudo apt-get install -y ${pkgs[*]}"
    BLOCKED+=("apt: ${pkgs[*]}")
    return 1
  fi
  sudo_do apt-get update -qq || true
  if sudo_do apt-get install -y "${pkgs[@]}"; then
    ok "apt: ${pkgs[*]}"
    return 0
  fi
  fail "apt no pudo instalar: ${pkgs[*]}"
  BLOCKED+=("apt: ${pkgs[*]}")
  return 1
}

_have_dockerd() {
  have dockerd || [[ -x /usr/bin/dockerd ]]
}

_install_docker_engine() {
  # Paquete a medias (wipe borró /usr/bin/docker): apt install no-op.
  # Hay que --reinstall y comprobar dockerd, no solo el código de apt.
  if have apt-get; then
    info "instalo Docker Engine con apt (docker.io + containerd)"
    sudo_do apt-get update -qq || true
    sudo_do apt-get install -y docker.io containerd || true
    hash -r 2>/dev/null || true
    if ! have docker || ! _have_dockerd; then
      info "paquete a medias; reinstalo docker.io"
      sudo_do apt-get install -y --reinstall docker.io containerd || true
      hash -r 2>/dev/null || true
    fi
    if have docker && _have_dockerd; then
      ok "Docker Engine (apt docker.io)"
      return 0
    fi
    warn "apt dejó Docker incompleto; pruebo get.docker.com"
  fi
  if ! have curl; then
    fail "sin curl no descargo get.docker.com"
    return 1
  fi
  info "instalador oficial get.docker.com"
  local shf=""
  shf="$(umask 077; mktemp "${TMPDIR:-/tmp}/aegis-get-docker.XXXXXX")" || {
    fail "no pude crear un temporal exclusivo para get.docker.com"
    return 1
  }
  if ! curl -fsSL https://get.docker.com -o "$shf"; then
    rm -f "$shf"
    fail "no pude descargar get.docker.com"
    return 1
  fi
  chmod 700 "$shf"
  if ! sudo_do sh "$shf"; then
    rm -f "$shf"
    fail "get.docker.com falló"
    return 1
  fi
  rm -f "$shf"
  hash -r 2>/dev/null || true
  if have docker && _have_dockerd; then
    ok "Docker Engine instalado"
    return 0
  fi
  fail "no quedó el binario docker/dockerd"
  return 1
}

_start_docker_daemon() {
  sudo_do systemctl unmask docker docker.socket containerd >/dev/null 2>&1 || true
  sudo_do systemctl enable containerd docker.socket docker >/dev/null 2>&1 || true
  sudo_do systemctl start containerd >/dev/null 2>&1 || true
  if sudo_do systemctl start docker; then
    return 0
  fi
  if sudo_do service docker start; then
    return 0
  fi
  warn "no arrancó el daemon docker"
  sudo -n journalctl -u docker -n 20 --no-pager 2>/dev/null || true
  return 1
}

_docker_info_sudo() {
  sudo -n docker info >/dev/null 2>&1
}

try_install_docker() {
  if have docker && docker_talks; then return 0; fi
  if (( DO_CHECK )); then return 1; fi
  step "1b" "Docker Engine + grupo docker"
  if ! need_root "instalar Docker Engine y añadir a $USER al grupo docker"; then
    fail "sin permiso no instalo Docker"
    note "sudo apt-get install -y docker.io"
    note "sudo groupadd -f docker && sudo usermod -aG docker $USER"
    BLOCKED+=("Docker Engine (sudo)")
    return 1
  fi
  # groupdel en un wipe deja el binario: usermod revienta si no recreamos el grupo.
  if ! sudo_do groupadd -f docker; then
    fail "no pude crear el grupo docker"
    BLOCKED+=("grupo docker")
    return 1
  fi
  if ! have docker || ! _have_dockerd || ! _docker_info_sudo; then
    if ! _install_docker_engine; then
      BLOCKED+=("Docker Engine")
      return 1
    fi
  fi
  if ! sudo_do groupadd -f docker; then
    fail "no pude crear el grupo docker"
    BLOCKED+=("grupo docker")
    return 1
  fi
  _start_docker_daemon || true
  if _user_in_docker_db; then
    ok "usuario $USER ya está en el grupo docker"
  elif sudo_do usermod -aG docker "$USER"; then
    ADDED_DOCKER_GROUP=1
    ok "usuario $USER → grupo docker"
  else
    fail "no pude añadir a $USER al grupo docker"
    BLOCKED+=("grupo docker ($USER)")
    return 1
  fi
  if command docker info >/dev/null 2>&1; then
    ok "daemon Docker responde (esta sesión)"
    return 0
  fi
  # grupo nuevo: esta shell aún no lo tiene → sudo docker para construir la imagen
  USE_SUDO_DOCKER=1
  if as_docker info >/dev/null 2>&1; then
    ok "daemon OK vía sudo (esta sesión no tiene el grupo todavía)"
    warn "antes del primer run: cierra sesión y vuelve a entrar (grupo docker)"
    return 0
  fi
  fail "Docker instalado pero el daemon no responde"
  BLOCKED+=("Docker daemon")
  return 1
}

install_python_deps() {
  step "2/8" "Dependencias Python"
  local py
  py="$(pick_python || true)"
  if [[ -z "$py" ]]; then
    fail "sin Python $MIN_PY+; salto pip"
    return 1
  fi
  if "$py" -c "import yaml" 2>/dev/null; then
    ok "PyYAML ya está ($("$py" -c 'import yaml; print(yaml.__version__)'))"
    return 0
  fi
  if (( DO_CHECK )); then
    fail "falta PyYAML (pip install -r requirements.txt)"
    BLOCKED+=("PyYAML")
    return 1
  fi
  if have apt-get && ensure_sudo; then
    if sudo_do apt-get install -y -qq python3-yaml >/dev/null 2>&1; then
      if "$py" -c "import yaml" 2>/dev/null; then
        ok "python3-yaml (apt)"
        return 0
      fi
    fi
  fi
  local pip_flags=(install --user -r "$ROOT/requirements.txt")
  if ! "$py" -m pip "${pip_flags[@]}" >/tmp/aegis-pip.log 2>&1; then
    pip_flags=(install --user --break-system-packages -r "$ROOT/requirements.txt")
    if ! "$py" -m pip "${pip_flags[@]}" >/tmp/aegis-pip.log 2>&1; then
      fail "pip no pudo instalar PyYAML"
      note "sudo apt-get install -y python3-yaml"
      note "o: $py -m pip install --user --break-system-packages -r requirements.txt"
      BLOCKED+=("PyYAML")
      return 1
    fi
  fi
  if "$py" -c "import yaml" 2>/dev/null; then
    ok "PyYAML (pip --user)"
    return 0
  fi
  fail "PyYAML sigue sin importar"
  BLOCKED+=("PyYAML")
  return 1
}

install_opencode() {
  step "3/8" "OpenCode (host)"
  ensure_path
  if [[ -x "$HOME/.opencode/bin/opencode" ]] || have opencode; then
    ok "OpenCode $(ver_of opencode || "$HOME/.opencode/bin/opencode" --version 2>/dev/null | head -1)"
    return 0
  fi
  if (( DO_CHECK )); then
    warn "OpenCode no está (opcional; Grok y modelos OpenCode)"
    note "curl -fsSL https://opencode.ai/install | bash"
    MISSING+=("OpenCode")
    return 1
  fi
  if ! ask_optional "¿Instalo OpenCode? Solo para Grok y el resto de modelos OpenCode"; then
    ok "OpenCode omitido"
    note "luego: curl -fsSL https://opencode.ai/install | bash"
    note "Aegis lo detecta al refrescar Modelos; Lanzar lo muestra entonces"
    return 0
  fi
  if ! have curl; then
    fail "sin curl no instalo OpenCode"
    MISSING+=("OpenCode")
    return 1
  fi
  info "descargo el instalador oficial → ~/.opencode/bin"
  if run_official_script "https://opencode.ai/install" bash; then
    ensure_path
    if [[ -x "$HOME/.opencode/bin/opencode" ]] || have opencode; then
      ok "OpenCode $(ver_of opencode || "$HOME/.opencode/bin/opencode" --version 2>/dev/null | head -1)"
      return 0
    fi
  fi
  fail "el instalador de OpenCode no dejó binario"
  note "curl -fsSL https://opencode.ai/install | bash"
  MISSING+=("OpenCode")
  return 1
}

install_claude() {
  step "4/8" "Claude Code (host)"
  ensure_path
  if [[ -x "$HOME/.local/bin/claude" ]] || have claude; then
    ok "Claude Code $(ver_of claude || "$HOME/.local/bin/claude" --version 2>/dev/null | head -1)"
    mkdir -p "$HOME/.claude"
    chmod 700 "$HOME/.claude" 2>/dev/null || true
    return 0
  fi
  if (( DO_CHECK )); then
    warn "Claude Code no está (opcional; solo modelos Claude)"
    note "curl -fsSL https://claude.ai/install.sh | bash"
    MISSING+=("Claude Code")
    return 1
  fi
  if ! ask_optional "¿Instalo Claude Code? Solo para el harness Claude"; then
    ok "Claude Code omitido"
    note "luego: curl -fsSL https://claude.ai/install.sh | bash"
    note "Aegis lo detecta al refrescar Modelos; Lanzar lo muestra entonces"
    return 0
  fi
  if ! have curl; then
    fail "sin curl no instalo Claude Code"
    MISSING+=("Claude Code")
    return 1
  fi
  info "descargo el instalador nativo oficial"
  if run_official_script "https://claude.ai/install.sh" bash; then
    ensure_path
    if [[ -x "$HOME/.local/bin/claude" ]] || have claude; then
      ok "Claude Code $(ver_of claude || "$HOME/.local/bin/claude" --version 2>/dev/null | head -1)"
      mkdir -p "$HOME/.claude"
      chmod 700 "$HOME/.claude" 2>/dev/null || true
      return 0
    fi
  fi
  fail "el instalador de Claude Code no dejó binario"
  note "curl -fsSL https://claude.ai/install.sh | bash"
  MISSING+=("Claude Code")
  return 1
}

find_codex_host() {
  local p dest
  for p in \
    "$HOME/.local/bin/codex-code-mode-host" \
    "$HOME/.codex/packages/standalone/current/bin/codex-code-mode-host" \
    "$HOME/.npm-global/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex-code-mode-host"
  do
    if [[ -x "$p" ]]; then printf '%s' "$p"; return 0; fi
  done
  local base
  base="$(command -v codex 2>/dev/null || true)"
  if [[ -z "$base" && -x "$HOME/.local/bin/codex" ]]; then
    base="$HOME/.local/bin/codex"
  fi
  if [[ -n "$base" ]]; then
    if [[ -x "$(dirname "$base")/codex-code-mode-host" ]]; then
      printf '%s' "$(dirname "$base")/codex-code-mode-host"
      return 0
    fi
    # En Linux el instalador oficial no pone el host en ~/.local/bin;
    # vive junto al ELF real (el de ~/.local/bin/codex es un symlink).
    dest="$(readlink -f "$base" 2>/dev/null || true)"
    if [[ -n "$dest" && -x "$(dirname "$dest")/codex-code-mode-host" ]]; then
      printf '%s' "$(dirname "$dest")/codex-code-mode-host"
      return 0
    fi
  fi
  # junto al ELF musl, no al wrapper npm
  python3 - <<'PY' 2>/dev/null || true
import os, shutil
from pathlib import Path
home = Path.home()
cands = []
w = shutil.which("codex")
if w:
    cands.append(Path(w))
cands += [
    home / ".local" / "bin" / "codex",
    home / ".npm-global" / "lib" / "node_modules" / "@openai" / "codex"
    / "node_modules" / "@openai" / "codex-linux-x64" / "vendor"
    / "x86_64-unknown-linux-musl" / "bin" / "codex",
]
hosts = [
    home / ".codex" / "packages" / "standalone" / "current" / "bin" / "codex-code-mode-host",
]
for c in cands:
    try:
        if not (c.is_file() and c.read_bytes()[:4] == b"\x7fELF"):
            continue
        hosts.append(c.parent / "codex-code-mode-host")
        hosts.append(c.resolve().parent / "codex-code-mode-host")
    except OSError:
        pass
for h in hosts:
    try:
        if h.is_file() and os.access(h, os.X_OK):
            print(h)
            raise SystemExit
    except OSError:
        pass
PY
}

install_codex() {
  step "5/8" "Codex CLI (host)"
  ensure_path
  local have_bin=0
  if have codex || [[ -x "$HOME/.local/bin/codex" ]]; then have_bin=1; fi
  if (( have_bin == 0 )); then
    if (( DO_CHECK )); then
      warn "Codex CLI no está (opcional; solo el harness ChatGPT / Codex)"
      note "curl -fsSL https://chatgpt.com/codex/install.sh | sh"
      MISSING+=("Codex CLI")
      return 1
    fi
    if ! ask_optional "¿Instalo Codex CLI? Solo para el harness ChatGPT / Codex"; then
      ok "Codex omitido"
      note "luego: curl -fsSL https://chatgpt.com/codex/install.sh | sh"
      note "Aegis lo detecta al refrescar Modelos; Lanzar lo muestra entonces"
      return 0
    fi
    if have curl; then
      info "descargo el instalador oficial (sin Node; no arranco Codex)"
      # "Start Codex now? [y/N]" — si se responde a mano o con Ctrl+C, para el install.sh.
      if run_official_script "https://chatgpt.com/codex/install.sh" sh "n"; then
        ensure_path
        if have codex || [[ -x "$HOME/.local/bin/codex" ]]; then
          have_bin=1
        fi
      fi
    fi
    if (( have_bin == 0 )) && have npm; then
      info "reintento por npm -g @openai/codex"
      mkdir -p "$HOME/.npm-global"
      npm config set prefix "$HOME/.npm-global" >/dev/null 2>&1 || true
      if npm install -g @openai/codex >/tmp/aegis-npm-codex.log 2>&1; then
        have_bin=1
      fi
    fi
  fi
  ensure_path
  if have codex || [[ -x "$HOME/.local/bin/codex" ]]; then
    ok "Codex $(ver_of codex || "$HOME/.local/bin/codex" --version 2>/dev/null | head -1)"
    mkdir -p "$HOME/.codex"
    if [[ ! -f "$HOME/.codex/config.toml" ]]; then
      : > "$HOME/.codex/config.toml"
      chmod 600 "$HOME/.codex/config.toml" 2>/dev/null || true
    fi
    chmod 700 "$HOME/.codex" 2>/dev/null || true
  else
    fail "no pude instalar Codex CLI"
    note "curl -fsSL https://chatgpt.com/codex/install.sh | sh"
    note "o: npm install -g @openai/codex   (hace falta Node)"
    MISSING+=("Codex CLI")
    return 1
  fi
  local host
  host="$(find_codex_host || true)"
  if [[ -n "$host" ]]; then
    ok "code-mode-host · $host"
  else
    warn "no veo codex-code-mode-host (el sandbox lo monta; sin él Codex no ejecuta)"
    note "reinstala Codex o exporta CODEX_CODE_MODE_HOST_BIN=/ruta/al/binario"
    MISSING+=("codex-code-mode-host")
  fi
  return 0
}

layout_data() {
  step "6/8" "Árbol data/ y permisos"
  mkdir -p "$ROOT/data/runs" "$ROOT/data/web/inbox"
  chmod 755 "$ROOT/data" "$ROOT/data/runs" "$ROOT/data/web" "$ROOT/data/web/inbox" 2>/dev/null || true
  # El bind mount usa los permisos del host, no los del Dockerfile.
  if ! chmod 755 \
    "$ROOT/aegis" \
    "$ROOT/aegis-web" \
    "$ROOT/install.sh" \
    "$ROOT/images/runner/entrypoint.sh"; then
    fail "no pude dar permisos de ejecucion a los scripts de Aegis"
    BLOCKED+=("permisos de ejecucion")
    return 1
  fi
  ok "data/runs + data/web/inbox"
}

install_web() {
  step "7/8" "UI (systemd --user ${WEB_HOST}:${WEB_PORT})"
  if (( SKIP_WEB )); then
    info "omitido (--skip-web)"
    return 0
  fi
  local py
  py="$(pick_python || command -v python3)"
  local unit_src="$ROOT/contrib/systemd/aegis-web.service"
  local unit_dst="$HOME/.config/systemd/user/aegis-web.service"
  if [[ ! -f "$unit_src" ]]; then
    fail "falta $unit_src"
    BLOCKED+=("unidad systemd aegis-web")
    return 1
  fi
  if (( DO_CHECK )); then
    if [[ -f "$unit_dst" ]]; then
      if ! grep -Fq -- "--host ${WEB_HOST}" "$unit_dst" \
        || ! grep -Fq -- "--port ${WEB_PORT}" "$unit_dst"; then
        warn "aegis-web.service no escucha en ${WEB_HOST}:${WEB_PORT}"
        note "relanza ./install.sh para regenerar la unidad con AEGIS_WEB_HOST / AEGIS_WEB_PORT"
        BLOCKED+=("aegis-web.service bind ${WEB_HOST}:${WEB_PORT}")
      fi
    fi
    if systemctl --user is-active --quiet aegis-web.service 2>/dev/null; then
      ok "aegis-web.service activo · ${WEB_HOST}:${WEB_PORT}"
    else
      fail "aegis-web.service no está activo"
      BLOCKED+=("aegis-web.service")
    fi
    return 0
  fi
  mkdir -p "$HOME/.config/systemd/user"
  chmod 755 "$ROOT/contrib/systemd/aegis-web-exec.sh" 2>/dev/null || true
  if ! write_web_unit "$unit_src" "$unit_dst" "$ROOT" "$py" "$WEB_HOST" "$WEB_PORT"; then
    fail "no pude escribir $unit_dst"
    BLOCKED+=("aegis-web.service")
    return 1
  fi
  if ! have systemctl; then
    warn "sin systemd: arranca la UI a mano"
    note "$py $ROOT/aegis-web --host $WEB_HOST --port $WEB_PORT"
    BLOCKED+=("systemd --user (UI como servicio)")
    return 1
  fi
  systemctl --user daemon-reload
  stop_stale_web "$ROOT"
  # restart: si linger tenía la unidad vieja, recarga el wrapper (grupo docker).
  if systemctl --user enable aegis-web.service \
    && systemctl --user restart aegis-web.service; then
    ok "aegis-web.service enabled + running · ${WEB_HOST}:${WEB_PORT}"
  else
    fail "no pude arrancar aegis-web.service"
    note "$py $ROOT/aegis-web --host $WEB_HOST --port $WEB_PORT"
    BLOCKED+=("aegis-web.service")
    return 1
  fi
  if loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then
    ok "linger activo (UI sigue al logout y al reiniciar)"
  else
    if need_root "loginctl enable-linger $USER (UI sigue al logout y al reiniciar)" \
      && sudo_do loginctl enable-linger "$USER" 2>/dev/null; then
      ok "linger activado (UI sigue al logout y al reiniciar)"
    else
      warn "sin linger la UI muere al cerrar sesión"
      note "sudo loginctl enable-linger $USER"
      MISSING+=("loginctl enable-linger")
    fi
  fi
  sleep 1
  if curl -fsS -m3 "http://127.0.0.1:${WEB_PORT}/" >/dev/null 2>&1; then
    ok "UI responde en http://127.0.0.1:${WEB_PORT}/"
  else
    warn "servicio arriba pero / aún no responde; mira journalctl --user -u aegis-web"
  fi
}

build_image() {
  step "8/8" "Imagen sandbox $IMAGE"
  if (( SKIP_IMAGE )); then
    info "omitido (--skip-image). Luego: docker build -t $IMAGE images/runner"
    return 0
  fi
  if ! have docker || ! docker_talks; then
    fail "sin Docker no construyo la imagen"
    BLOCKED+=("imagen $IMAGE")
    return 1
  fi
  if as_docker image inspect "$IMAGE" >/dev/null 2>&1; then
    local sz
    sz="$(as_docker image inspect "$IMAGE" --format '{{.Size}}' 2>/dev/null || echo 0)"
    sz="$(python3 -c "print(f'{int(\"$sz\")/1_000_000_000:.1f} GB')" 2>/dev/null || echo "?")"
    if (( DO_CHECK )); then
      ok "imagen $IMAGE ya está ($sz)"
      return 0
    fi
    if ! confirm "ya existe $IMAGE ($sz). ¿la reconstruyo?"; then
      ok "me quedo con la imagen que ya hay ($sz)"
      return 0
    fi
  elif (( DO_CHECK )); then
    fail "falta la imagen $IMAGE (docker build -t $IMAGE images/runner)"
    note "tarda y pesa ~31 GB. En un host nuevo: ./install.sh  (o --skip-image si ahora no cabe)"
    MISSING+=("imagen $IMAGE")
    return 1
  fi
  info "Kali headless + herramientas + OpenCode dentro. Tarda. No lo pares."
  local blog
  blog="$(mktemp "${TMPDIR:-/tmp}/aegis-docker-build.XXXXXX")"
  if ! as_docker build -t "$IMAGE" "$ROOT/images/runner" > >(tee "$blog") 2>&1; then
    if grep -qE 'blob not found|failed to lease content' "$blog" 2>/dev/null; then
      warn "containerd tiene capas a medias (pasa si se borró Docker y se reinstaló)"
      if repair_docker_base; then
        info "reintento el build con Kali limpia"
        if as_docker build -t "$IMAGE" "$ROOT/images/runner"; then
          rm -f "$blog"
          ok "imagen $IMAGE lista"
          return 0
        fi
      fi
    else
      warn "docker build falló; reintento una vez (la capa de Kali se reutiliza)"
      if as_docker build -t "$IMAGE" "$ROOT/images/runner"; then
        rm -f "$blog"
        ok "imagen $IMAGE lista"
        return 0
      fi
    fi
    rm -f "$blog"
    fail "docker build falló"
    note "vuelve a: docker build -t $IMAGE images/runner"
    note "si falló OpenCode, no relances ./install.sh entero: la capa apt ya está"
    BLOCKED+=("imagen $IMAGE")
    return 1
  fi
  rm -f "$blog"
  ok "imagen $IMAGE lista"
  if (( DO_SLIM )); then
    info "construyo también $SLIM (smoke)"
    if as_docker build -f "$ROOT/images/runner/Dockerfile.slim" -t "$SLIM" "$ROOT/images/runner"; then
      ok "imagen $SLIM lista"
    else
      warn "slim falló; la completa sí está"
      MISSING+=("imagen $SLIM")
    fi
  fi
}

run_doctor() {
  local py
  py="$(pick_python || command -v python3 || true)"
  [[ -n "$py" ]] || return 0
  step "ok" "aegis doctor"
  local cmd=( "$py" ./aegis doctor )
  if have sg && id -nG "$USER" 2>/dev/null | grep -qw docker \
    && ! id -nG 2>/dev/null | grep -qw docker; then
    if ( cd "$ROOT" && sg docker -c "$(printf '%q ' "${cmd[@]}")" ); then
      ok "doctor terminó"
    else
      warn "doctor avisa (normal si aún no hay logins: eso va en la UI → Modelos)"
    fi
    return 0
  fi
  if ( cd "$ROOT" && "${cmd[@]}" ); then
    ok "doctor terminó"
  else
    warn "doctor avisa (normal si aún no hay logins: eso va en la UI → Modelos)"
  fi
}

summary() {
  printf '\n%s╭──────────────────────────────────────────╮%s\n' "$CA" "$C0"
  printf '%s│  resumen                                 │%s\n' "$CA" "$C0"
  printf '%s╰──────────────────────────────────────────╯%s\n' "$CA" "$C0"
  if (( ${#BLOCKED[@]} )); then
    printf '\n  %sNo pude dejar el host listo:%s\n' "$CR" "$C0"
    local x
    for x in "${BLOCKED[@]}"; do printf '    %s✗%s  %s\n' "$CR" "$C0" "$x"; done
    printf '\n  %sInstala eso a mano y vuelve a ejecutar ./install.sh%s\n' "$CDIM" "$C0"
  fi
  if (( ${#MISSING[@]} )); then
    printf '\n  %sFalta, pero no bloquea el resto:%s\n' "$CY" "$C0"
    local x
    for x in "${MISSING[@]}"; do printf '    %s!%s  %s\n' "$CY" "$C0" "$x"; done
  fi
  if (( ${#BLOCKED[@]} == 0 )); then
    if (( DO_CHECK )); then
      printf '\n  %sDiagnóstico: el modo pedido puede operar.%s  UI en %shttp://127.0.0.1:%s/%s\n' \
        "$CG" "$C0" "$CB" "$WEB_PORT" "$C0"
    else
      printf '\n  %sEl software está instalado.%s  Te falta solo esto (el script no lo hace):\n' "$CG" "$C0"
      printf '    %s1.%s  Abre  %shttp://127.0.0.1:%s/%s\n' "$CA" "$C0" "$CB" "$WEB_PORT" "$C0"
      printf '    %s2.%s  Pestaña %sModelos%s → login Grok, ChatGPT y/o Claude\n' "$CA" "$C0" "$CB" "$C0"
      printf '    %s3.%s  Sin esas cuentas el run no tiene modelo. Luego: Lanzar.\n' "$CA" "$C0"
    fi
    if (( ADDED_DOCKER_GROUP )); then
      printf '\n  %sGrupo docker:%s la UI ya lo usa (no hace falta cerrar sesión para ver la imagen).\n' "$CY" "$C0"
      printf '  %sEn un terminal abierto de antes, `docker` a pelo puede fallar; abre uno nuevo.%s\n' "$CY" "$C0"
    fi
  fi
  printf '\n'
  if (( ${#BLOCKED[@]} )); then return 1; fi
  return 0
}

if ! valid_web_bind; then
  exit 2
fi

banner

if (( DO_PACK )); then
  pack_zip "$PACK_OUT"
  exit $?
fi

if (( DO_WIPE )); then
  wipe_install
  exit 0
fi

preflight
if [[ " ${BLOCKED[*]} " == *" Linux "* ]]; then
  summary
  exit 1
fi
if (( ! DO_CHECK )); then
  try_apt_min || true
  try_install_docker || true
fi

if (( IMAGE_ONLY )); then
  build_image
  summary
  exit $?
fi

install_python_deps || true
if (( ! DO_CHECK )); then
  ensure_path
  info "PATH de usuario: ~/.opencode/bin · ~/.local/bin · ~/.npm-global/bin"
fi
install_opencode || true
install_claude || true
install_codex || true
if (( ! DO_CHECK )); then
  if ! layout_data; then
    summary
    exit 1
  fi
fi
install_web || true
build_image || true

if (( ! DO_CHECK )); then
  run_doctor || true
fi
summary
