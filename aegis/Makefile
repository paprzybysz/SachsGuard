.PHONY: sync test serve demo docker-up docker-down ollama

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

serve:
	AEGIS_ROOT=$(PWD) AEGIS_PROFILE=$(PROFILE) $(RUN)aegis serve --host 127.0.0.1 --port 8080

demo:
	AEGIS_ROOT=$(PWD) $(RUN)aegis demo-agent --base-url http://127.0.0.1:8080 --scenario all

# Pull the local model used by the semantic LLM judge.
ollama:
	ollama pull gemma3:4b

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v
