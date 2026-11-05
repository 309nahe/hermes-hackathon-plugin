.PHONY: validate test enable doctor bootstrap

PLUGIN_NAME ?= hermes-hackathon-plugin
HERMES_HOME ?= $(HOME)/.hermes

validate:
	hermes plugins validate . --install-deps

doctor:
	HERMES_PLUGINS_DEBUG=1 hermes plugins doctor . 2>&1 | tail -30

test:
	cd /tmp && python -m pytest -q $(CURDIR)/tests/ 2>/dev/null || python3 -m pytest -q $(CURDIR)/tests/

enable:
	hermes plugins enable $(PLUGIN_NAME)

bootstrap:
	./scripts/bootstrap.sh
