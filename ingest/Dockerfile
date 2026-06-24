FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 514/udp
EXPOSE 6514
EXPOSE 8001

CMD ["python", "-m", "ingest.main"]
