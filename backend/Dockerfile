FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl libmagic1 nmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r cybershield && useradd -r -g cybershield -d /app cybershield

COPY requirements.txt .
RUN pip install --default-timeout=1000 --retries 10 -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
RUN mkdir -p /app/generated_reports /app/models /app/quarantine \
    && chown -R cybershield:cybershield /app

USER cybershield

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8000/api/v1/health || exit 1
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
