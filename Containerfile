FROM python:3.12.12-slim-bookworm

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y openssh-client \
    && groupadd --gid 65532 homeops \
    && useradd --uid 65532 --gid 65532 --home-dir /var/lib/homeops-client --create-home --shell /usr/sbin/nologin homeops \
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
