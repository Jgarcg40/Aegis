#!/bin/bash
# Instala el inventario de herramientas. Los fallos de paquetes opcionales
# no tiran la imagen: se registran en /opt/aegis/MISSING.txt
# Uso: install-tools.sh [apt|opencode|all]
# apt y opencode van en capas Docker distintas: si OpenCode falla, el
# rebuild reutiliza Kali y no empieza de cero.
set -u
export DEBIAN_FRONTEND=noninteractive
MISSING=/opt/aegis/MISSING.txt
mkdir -p /opt/aegis

STAGE="${1:-all}"
case "$STAGE" in
  apt|all) : >"$MISSING" ;;
  opencode) touch "$MISSING" ;;
  *)
    echo "uso: $0 [apt|opencode|all]" >&2
    exit 2
    ;;
esac

apt_try() {
  local n=0
  while (( n < 3 )); do
    if apt-get "$@"; then
      return 0
    fi
    n=$((n + 1))
    echo "[aegis] apt reintento ${n}/3: $*" >&2
    sleep $((n * 3))
    apt-get update || true
  done
  return 1
}

apt_ok() {
  if apt_try install -y --no-install-recommends "$@"; then
    return 0
  fi
  echo "$*" >>"$MISSING"
  echo "[aegis] aviso: no se instaló: $*" >&2
  return 0
}

# http.kali.org redirige a mirrors regionales. En ES a menudo cae
# mirror.es.cdn-perfprod.com y apt pierde paquetes (o el update entero).
pin_kali_mirrors() {
  mkdir -p /etc/apt/apt.conf.d
  cat >/etc/apt/apt.conf.d/80aegis-retries <<'EOF'
Acquire::Retries "5";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
Acquire::http::Pipeline-Depth "0";
EOF
  local f
  if [[ -d /etc/apt/sources.list.d ]]; then
    for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
      [[ -e "$f" ]] || continue
      rm -f "$f"
    done
  fi
}

apt_update_pinned() {
  local mirrors=(
    "http://kali.download/kali"
    "http://mirror.raiolanetworks.com/kali"
    "http://http.kali.org/kali"
  )
  local m
  pin_kali_mirrors
  for m in "${mirrors[@]}"; do
    cat >/etc/apt/sources.list <<EOF
deb ${m} kali-rolling main contrib non-free non-free-firmware
EOF
    echo "[aegis] apt update vía ${m}" >&2
    if apt-get update; then
      return 0
    fi
    echo "[aegis] aviso: apt update falló en ${m}" >&2
  done
  echo "FATAL: apt-get update (ningún mirror Kali respondió)" >&2
  exit 1
}

_strip_nmap_caps() {
  local src=/usr/lib/nmap/nmap
  [[ -x "$src" ]] || return 0
  if command -v setcap >/dev/null 2>&1; then
    setcap -r "$src" 2>/dev/null && return 0
  fi
  local tmp=/tmp/.nmap.bin.$$
  cp "$src" "$tmp"
  chmod 0755 "$tmp"
  mv -f "$tmp" "$src"
}

have_downloader() {
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1
}

# apt es transaccional: si un meta (jre, node, …) no se puede bajar,
# no instala NADA del mismo comando — ni curl. Por eso el bootstrap va solo.
install_bootstrap() {
  if ! apt_try install -y --no-install-recommends ca-certificates curl wget; then
    echo "FATAL: no pude instalar curl/wget (bootstrap)" >&2
    exit 1
  fi
  if ! have_downloader; then
    echo "FATAL: curl y wget siguen ausentes tras el bootstrap" >&2
    exit 1
  fi
}

http_get() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$@"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O- --tries=3 --timeout=20 "$@"
  else
    return 1
  fi
}

http_get_file() {
  local dest="$1"
  shift
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 -o "$dest" "$@"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" --tries=3 --timeout=20 "$@"
  else
    return 1
  fi
}

install_apt_inventory() {
  apt_update_pinned
  install_bootstrap

  # El resto del base no puede tumbar la imagen si un paquete falla.
  apt_ok git jq tmux vim-tiny less file \
    python3 python3-pip python3-venv python3-dev \
    gcc g++ make cmake pkg-config \
    build-essential gdb strace ltrace \
    unzip zip p7zip-full xz-utils \
    iproute2 iputils-ping net-tools dnsutils whois \
    procps psmisc lsof \
    openssh-client sshpass ncat socat netcat-traditional \
    openssl gnupg \
    rsync sqlite3 \
    bash-completion \
    locales \
    libpcap0.8 \
    default-jre-headless

  # Kali metas (headless = sin GUI). Si el meta no existe, seguimos con grupos.
  if ! apt_try install -y kali-linux-headless; then
    echo "kali-linux-headless" >>"$MISSING"
    apt_ok kali-tools-top10
    apt_ok kali-tools-information-gathering
    apt_ok kali-tools-vulnerability
    apt_ok kali-tools-web
    apt_ok kali-tools-database
    apt_ok kali-tools-passwords
    apt_ok kali-tools-exploitation
    apt_ok kali-tools-post-exploitation
    apt_ok kali-tools-sniffing-spoofing
    apt_ok kali-tools-reverse-engineering
    apt_ok kali-tools-forensics
    apt_ok kali-tools-windows-resources
  fi

  # Recon / superficie
  apt_ok nmap masscan rustscan naabu
  # Kali pone filecaps en nmap (cap_net_raw=eip). Con Docker no-new-privileges
  # el kernel niega el exec ("Operation not permitted"). Root + NET_RAW del
  # contenedor bastan; quitamos las filecaps (y si setcap falla, copiamos el ELF).
  _strip_nmap_caps
  apt_ok amass theharvester recon-ng spiderfoot
  apt_ok dnsrecon dnsenum dnsmap dnstracer fierce
  apt_ok whatweb wafw00f httpx-toolkit subfinder katana
  apt_ok gobuster ffuf feroxbuster dirb dirbuster wfuzz arjun
  apt_ok nikto nuclei wpscan joomscan droopescan
  apt_ok sslscan sslyze testssl.sh
  apt_ok snmpcheck onesixtyone braa
  apt_ok nbtscan enum4linux enum4linux-ng smbmap smbclient
  apt_ok rpcbind rpcclient
  apt_ok ldap-utils ldapdomaindump
  apt_ok ike-scan onesixtyone

  # AD / Windows desde Linux
  apt_ok impacket-scripts python3-impacket
  apt_ok bloodhound bloodhound.py bloodhound-ce-python
  apt_ok netexec crackmapexec
  apt_ok evil-winrm evil-winrm-py
  apt_ok certipy-ad bloodyad
  apt_ok responder ntlmrelayx
  apt_ok kerberoast krb5-user
  apt_ok evil-winrm
  apt_ok windows-binaries
  apt_ok wine wine64
  apt_ok mingw-w64
  apt_ok powershell-empire starkiller || true
  apt_ok powershell

  # Web / proxy CLI (Burp es GUI; se incluye si el paquete existe, ZAP/caido cubren headless)
  apt_ok burpsuite
  apt_ok zaproxy
  apt_ok caido-cli
  apt_ok mitmproxy
  apt_ok sqlmap
  apt_ok commix
  apt_ok jwt-tool
  apt_ok hakrawler
  apt_ok aquatone gowitness

  # Credenciales / hashes (offline + online cuando el modo lo permita)
  apt_ok hydra medusa ncrack patator
  apt_ok john john-data hashcat hashid hash-identifier
  apt_ok seclists wordlists cewl crunch cupp

  # Red / pivote / tunel
  apt_ok chisel
  apt_ok ligolo-ng ligolo-mp
  apt_ok proxychains4
  apt_ok openvpn wireguard-tools
  apt_ok tcpdump tshark ngrep
  apt_ok socat

  # Reverse / forense útil en caja
  apt_ok binwalk foremost steghide exiftool
  apt_ok radare2 gdb-peda
  apt_ok checksec
  apt_ok sleuthkit

  # Exploit helpers de sistema (no son playbooks; el agente decide)
  apt_ok exploitdb
  apt_ok metasploit-framework
  apt_ok python3-pwntools
  apt_ok gdb

  # Lenguajes extra que el agente suele necesitar
  apt_ok ruby ruby-dev perl golang-go rustc cargo
  apt_ok php-cli nodejs npm

  # Wordlists path típico de Kali
  if [[ -d /usr/share/wordlists && ! -e /usr/share/wordlists/rockyou.txt ]]; then
    if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
      gunzip -k /usr/share/wordlists/rockyou.txt.gz || true
    fi
  fi

  apt-get clean || true
  rm -rf /var/lib/apt/lists/* || true
  echo "[aegis] install-tools: capa apt FIN" >&2
}

find_opencode() {
  local c
  if command -v opencode >/dev/null 2>&1; then
    command -v opencode
    return 0
  fi
  for c in \
    /usr/local/bin/opencode \
    /usr/bin/opencode \
    /root/.opencode/bin/opencode \
    /root/.local/bin/opencode \
    "${HOME:-/root}/.opencode/bin/opencode" \
    "${HOME:-/root}/.local/bin/opencode"; do
    if [[ -x "$c" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

link_opencode() {
  local oc="$1"
  mkdir -p /usr/local/bin /root/.opencode/bin
  if [[ "$oc" != /usr/local/bin/opencode ]]; then
    ln -sfn "$oc" /usr/local/bin/opencode
  fi
  if [[ "$oc" != /root/.opencode/bin/opencode ]]; then
    ln -sfn /usr/local/bin/opencode /root/.opencode/bin/opencode 2>/dev/null \
      || cp -f /usr/local/bin/opencode /root/.opencode/bin/opencode
  fi
}

install_opencode_official() {
  local i
  export HOME="${HOME:-/root}"
  for i in 1 2 3; do
    echo "[aegis] OpenCode: instalador oficial (intento ${i}/3)" >&2
    if http_get https://opencode.ai/install | bash; then
      find_opencode >/dev/null && return 0
    fi
    echo "[aegis] aviso: instalador oficial OpenCode no dejó binario (${i}/3)" >&2
    sleep $((i * 2))
  done
  return 1
}

install_opencode_github() {
  local asset url dest tmp bin repo
  case "$(uname -m)" in
    aarch64|arm64) asset=opencode-linux-arm64.tar.gz ;;
    *) asset=opencode-linux-x64.tar.gz ;;
  esac
  dest=/tmp/opencode-gh.tgz
  tmp=$(mktemp -d)
  for repo in anomalyco/opencode sst/opencode; do
    url="https://github.com/${repo}/releases/latest/download/${asset}"
    echo "[aegis] OpenCode: ${url}" >&2
    if ! http_get_file "$dest" "$url"; then
      continue
    fi
    rm -rf "$tmp"
    tmp=$(mktemp -d)
    if ! tar -xzf "$dest" -C "$tmp"; then
      continue
    fi
    bin=$(find "$tmp" -type f -name opencode | head -n 1 || true)
    if [[ -z "$bin" || ! -f "$bin" ]]; then
      continue
    fi
    chmod 0755 "$bin"
    mkdir -p /usr/local/bin
    cp -f "$bin" /usr/local/bin/opencode
    rm -f "$dest"
    rm -rf "$tmp"
    find_opencode >/dev/null && return 0
  done
  rm -f "$dest"
  rm -rf "$tmp"
  return 1
}

install_opencode_and_go() {
  export GOPATH=/opt/go
  export HOME="${HOME:-/root}"
  export PATH="$PATH:/opt/go/bin:/usr/lib/go/bin:/usr/local/bin:${HOME}/.opencode/bin:${HOME}/.local/bin"
  mkdir -p /opt/go/bin
  if ! have_downloader; then
    echo "[aegis] aviso: sin curl/wget; reintento bootstrap" >&2
    apt_update_pinned
    install_bootstrap
  fi

  if command -v go >/dev/null 2>&1; then
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest || echo "httpx-go" >>"$MISSING"
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "nuclei-go" >>"$MISSING"
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "subfinder-go" >>"$MISSING"
    go install github.com/projectdiscovery/katana/cmd/katana@latest || echo "katana-go" >>"$MISSING"
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || echo "naabu-go" >>"$MISSING"
    go install github.com/ffuf/ffuf/v2@latest || echo "ffuf-go" >>"$MISSING"
    go install github.com/OJ/gobuster/v3@latest || echo "gobuster-go" >>"$MISSING"
    go install github.com/ropnop/kerbrute@latest || echo "kerbrute" >>"$MISSING"
  fi

  # OpenCode (binario oficial). El instalador ignora OPENCODE_INSTALL_DIR y
  # cae en ~/.opencode/bin; localizamos y enlazamos a /usr/local/bin.
  # No usar `find /`: en Docker recorre /proc y parece un hang eterno.
  local OC=""
  OC=$(find_opencode || true)
  if [[ -z "$OC" ]]; then
    install_opencode_official || true
    OC=$(find_opencode || true)
  fi
  if [[ -z "$OC" ]]; then
    install_opencode_github || true
    OC=$(find_opencode || true)
  fi
  echo "[aegis] opencode encontrado en: ${OC:-NADA}" >&2
  if [[ -n "$OC" ]]; then
    link_opencode "$OC"
    OC=$(find_opencode || true)
  fi
  if [[ -z "$OC" ]] || ! command -v opencode >/dev/null 2>&1; then
    echo "FATAL: opencode no quedó en PATH (oficial y GitHub fallaron)" >&2
    ls -la /root/.opencode/bin /usr/local/bin /root/.local/bin 2>/dev/null || true
    echo "opencode" >>"$MISSING"
    exit 1
  fi
  opencode --version || true
  echo "[aegis] install-tools: OpenCode OK, limpiando" >&2
  rm -rf /tmp/go-build* /tmp/opencode-gh.tgz || true
  echo "[aegis] install-tools: FIN" >&2
}

case "$STAGE" in
  apt) install_apt_inventory ;;
  opencode) install_opencode_and_go ;;
  all)
    install_apt_inventory
    install_opencode_and_go
    ;;
esac
