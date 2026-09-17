# Kali headless + OpenCode + herramientas. Root dentro; muere al terminar el run.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    OPENCODE_DISABLE_AUTOUPDATE=1

COPY install-tools.sh /tmp/install-tools.sh
COPY TOOLS.txt /opt/aegis/TOOLS.md
# Capa apt (Kali). Si OpenCode falla después, docker rebuild reutiliza esto.
RUN chmod +x /tmp/install-tools.sh \
    && /tmp/install-tools.sh apt
RUN /tmp/install-tools.sh opencode \
    && rm -f /tmp/install-tools.sh

COPY bash_audit.sh /etc/aegis/bash_audit.sh
COPY entrypoint.sh /usr/local/bin/aegis-entrypoint
RUN chmod 644 /etc/aegis/bash_audit.sh \
    && chmod 755 /usr/local/bin/aegis-entrypoint \
    && mkdir -p /workspace /run/aegis/brief /run/aegis/out

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/aegis-entrypoint"]
