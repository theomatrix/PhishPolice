# ── PhishPolice Backend – Dockerfile ─────────────────────────────
# Multi-stage build: builder installs deps, runtime image is lean.
#
# Build:   docker build -t phishpolice-backend .
# Run:     docker run -p 5000:5000 --env-file backend/.env phishpolice-backend
# Compose: docker compose up --build
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# gcc is required for some compiled wheels (e.g. python-whois, cryptography)
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt requirements.txt

RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Non-root user for security
RUN addgroup --system phish \
 && adduser --system --ingroup phish phish

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy backend source (excludes local venv via .dockerignore)
COPY backend/ .

ENV FLASK_APP=app.py \
    FLASK_DEBUG=false \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

USER phish

# Gunicorn: 2 workers, 120 s timeout (visual analysis can be slow)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]