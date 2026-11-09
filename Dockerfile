# PrintFlow: one container serves the website and the API.
# Secrets are NOT baked in: set them as environment variables on your host
# (same names as backend/.env.example).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/main.py backend/main.py
COPY frontend/ frontend/

RUN useradd --create-home appuser
USER appuser

# Hosts set $PORT. --proxy-headers makes rate limits / PIN lockout see each
# customer's real IP instead of the host's load balancer.
CMD ["sh", "-c", "uvicorn main:app --app-dir backend --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
