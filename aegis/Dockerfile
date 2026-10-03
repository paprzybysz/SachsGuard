FROM python:3.12-slim AS runtime

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies

RUN pip install --default-timeout=180 --no-cache-dir ".[redis]"

ENV AEGIS_ROOT=/app
ENV AEGIS_POLICY=/app/policies/policy.yaml
ENV AEGIS_DEMO_ECHO=1

EXPOSE 8080
CMD ["aegis", "serve", "--host", "0.0.0.0", "--port", "8080"]

# One-shot image for the business-requirement suite. The gateway image stays the
# runtime stage; `make docker-up` runs this stage against the Ollama service.
FROM runtime AS suite

RUN pip install --default-timeout=180 --no-cache-dir pytest pytest-asyncio
COPY tests ./tests
ENV PYTHONUNBUFFERED=1
