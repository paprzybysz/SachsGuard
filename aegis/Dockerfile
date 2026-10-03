FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies

RUN pip install --no-cache-dir .

ENV AEGIS_ROOT=/app
ENV AEGIS_POLICY=/app/policies/policy.yaml
ENV AEGIS_DEMO_ECHO=1

EXPOSE 8080
CMD ["aegis", "serve", "--host", "0.0.0.0", "--port", "8080"]
