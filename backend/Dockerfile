FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml requirements.lock ./
COPY app ./app
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.lock && /opt/venv/bin/pip install --no-deps .

FROM python:3.12-slim
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN groupadd --gid 10001 zerograph && useradd --uid 10001 --gid zerograph --create-home zerograph
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
