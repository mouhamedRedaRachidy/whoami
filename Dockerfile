FROM python:3.14-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /usr/local/bin/uv

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock ./

RUN uv sync --python /usr/local/bin/python \
    --no-python-downloads \
    --locked --no-dev --no-install-project

RUN useradd --create-home --shell /usr/sbin/nologin app

COPY . ./

USER app

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]