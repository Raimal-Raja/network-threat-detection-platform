FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-training.txt requirements-service.txt ./
RUN pip install --no-cache-dir -r requirements-service.txt && useradd --uid 10001 --create-home analyst
COPY threat_platform ./threat_platform
RUN mkdir -p /app/artifacts/analyst /app/artifacts/deployment && chown -R analyst:analyst /app/artifacts
USER analyst
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=3)"
CMD ["python", "-m", "uvicorn", "threat_platform.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
