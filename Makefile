PYTHON ?= python3
IMAGE ?= aegis-runner:latest
SLIM ?= aegis-runner:slim

WEB_HOST ?= 0.0.0.0
WEB_PORT ?= 8787

.PHONY: help install install-host image image-slim test smoke doctor web pack

help:
	@echo "make install-host — todo el host (CLIs, imagen, UI). Ver ./install.sh"
	@echo "make install      — dependencias Python"
	@echo "make image        — imagen Kali completa (lenta, varios GB)"
	@echo "make image-slim   — imagen Debian mínima para --smoke"
	@echo "make pack         — zip limpio (sin runs, logs ni .git)"
	@echo "make test         — tests unitarios (sin Docker)"
	@echo "make smoke        — ciclo crear/destruir contra 127.0.0.1"
	@echo "make doctor       — Docker + imagen + layout"
	@echo "make web          — UI on-premise en http://<host>:$(WEB_PORT)"

install-host:
	./install.sh -y

install:
	$(PYTHON) -m pip install -r requirements.txt

pack:
	./install.sh --pack

image:
	docker build -t $(IMAGE) images/runner

image-slim:
	docker build -f images/runner/Dockerfile.slim -t $(SLIM) images/runner

test:
	$(PYTHON) -m unittest discover -s tests -v

doctor:
	$(PYTHON) ./aegis doctor

smoke: image-slim
	$(PYTHON) ./aegis run --target 127.0.0.1 --i-am-authorized --smoke --image $(SLIM) --timeout 2m

web:
	$(PYTHON) ./aegis-web --host $(WEB_HOST) --port $(WEB_PORT)
