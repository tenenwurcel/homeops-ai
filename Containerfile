FROM python:3.12.12-slim-bookworm

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.9.30

WORKDIR /app
COPY README.md pyproject.toml uv.lock ./
COPY src ./src
COPY evaluation ./evaluation
RUN uv sync --frozen --no-dev --no-editable \
    && rm -rf /root/.cache/uv

USER 65532:65532
ENTRYPOINT ["homeops-ai"]
