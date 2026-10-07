FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONPATH=/srv
WORKDIR /srv
COPY pyproject.toml ./
# Install dependencies only (layer cached until pyproject changes); the code runs from /srv via PYTHONPATH.
RUN mkdir app && touch app/__init__.py && pip install . && pip uninstall -y threat-hunt-backend && rm -rf app
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
RUN useradd --system --uid 10001 hunt
USER hunt
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
