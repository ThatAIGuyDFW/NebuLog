FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy both workers and ingest (for models/parsers)
COPY ../workers ./workers
COPY ../ingest ./ingest

# Storage worker is the default; override CMD to run archive worker
CMD ["python", "-m", "workers.storage_worker"]
