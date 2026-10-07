# syntax=docker/dockerfile:1

FROM python:3.13-slim

# Python runtime settings
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_DEBUG=false

WORKDIR /app

# Create a dedicated non-root runtime user.
RUN groupadd --system phishlens \
    && useradd --system \
       --gid phishlens \
       --home-dir /app \
       --shell /usr/sbin/nologin \
       phishlens

# Install Python dependencies first for better Docker layer caching.
COPY requirements.txt .

RUN python -m pip install \
    --no-cache-dir \
    -r requirements.txt

# Copy application source.
COPY . .

# Runtime directory for the default SQLite database.
RUN mkdir -p /app/instance \
    && chown -R phishlens:phishlens /app \
    && chmod 755 /app/instance

USER phishlens

EXPOSE 5000

# Apply database migrations before starting the production WSGI server.
CMD ["sh", "-c", "alembic upgrade head && exec gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 wsgi:app"]