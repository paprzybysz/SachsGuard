.PHONY: sync test test-l3 serve demo docker-up docker-down docker-suite ollama

# Smallest instruct model Ollama publishes (135M parameters). The business suite
# judges with this tag; the gateway keeps the model named in policies/policy.yaml.
OLLAMA_MODEL ?= smollm2:135m

# Uses uv when installed, otherwise a plain venv (python3 -m venv .venv).
UV := $(shell command -v uv 2>/dev/null)
ifdef UV
RUN := uv run 
SYNC := uv sync --all-groups
else
RUN := .venv/bin/
SYNC := python3 -m venv .venv && .venv/bin/pip install -e . pytest pytest-asyncio
endif

# Profile from policies/policy.yaml; empty = its active_profile. e.g. make serve PROFILE=strict
PROFILE ?=

sync:
	$(SYNC)

test:
	$(RUN)pytest -v

# L3: business decisions through the HTTP API. Judge is local Ollama ($(OLLAMA_MODEL)).
test-l3:
	AEGIS_OLLAMA_MODEL=$(OLLAMA_MODEL) $(RUN)pytest tests/test_l3_api.py -v -m l3

serve:
	AEGIS_ROOT=$(PWD) AEGIS_PROFILE=$(PROFILE) $(RUN)aegis serve --host 127.0.0.1 --port 8080

demo:
	AEGIS_ROOT=$(PWD) $(RUN)aegis demo-agent --base-url http://127.0.0.1:8080 --scenario all

# Pull the local model used by the semantic LLM judge.
ollama:
	ollama pull gemma3:4b

docker-up:
	docker compose up --build -d
	docker compose up -d --wait ollama
	docker compose exec -T ollama ollama pull $(OLLAMA_MODEL)
	$(MAKE) docker-suite

# Business requirements against the Ollama service (description + verdict on stdout).
docker-suite:
	AEGIS_OLLAMA_MODEL=$(OLLAMA_MODEL) docker compose --profile suite run --rm --build business-suite

docker-down:
	docker compose down -v
