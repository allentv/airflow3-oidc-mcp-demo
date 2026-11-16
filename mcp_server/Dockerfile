FROM python:3.12-slim

WORKDIR /srv/mcp

# Install dependencies first for layer caching.
COPY pyproject.toml ./
COPY app/ ./app/
RUN pip install --no-cache-dir .

EXPOSE 8081
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]