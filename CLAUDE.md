# Sentinel — Hybrid SIEM & Log Intelligence Platform

## Language
- Python 3.12 (all backend services)
- TypeScript / React 18 (UI)
- HCL (Terraform infra)

## Local Dev Start
```bash
docker compose up -d                            # Redis 7 + PostgreSQL 16 + pgvector
cd db && alembic upgrade head                   # first run only (or let API auto-migrate)
cd ingest && python main.py                     # UDP 514 + TLS 6514 + HTTP 8001
cd api && uvicorn main:app --reload             # REST API on :8000 (auto-migrates)
cd workers && python storage_worker.py          # DB batch insert consumer
cd workers && python archive_worker.py          # Azure Blob archive consumer
cd correlation && python -m correlation.engine  # Correlation engine (APScheduler)
cd ui && npm run dev                            # React UI on http://localhost:3000
```

Windows agent (run as Administrator):
```powershell
cd agents\windows
python service.py install && python service.py start
```

Linux agent:
```bash
cd agents/linux
cp .env.example .env   # set SENTINEL_INGEST_URL
sudo systemctl enable --now sentinel-agent
```

## Run Tests
```bash
pytest tests/ -v --ignore=tests/integration    # unit tests (no Docker required)
pytest tests/integration/ -v -m integration    # requires docker compose up -d
```

## DB Migrations
```bash
cd db && alembic upgrade head     # manual run
cd db && alembic revision --autogenerate -m "description"   # generate new migration
```
The API service auto-runs `alembic upgrade head` in the lifespan startup hook.

## TLS Syslog (TCP 6514)
Set these env vars to enable the TLS listener:
```
INGEST_TLS_CERT=/path/to/cert.pem
INGEST_TLS_KEY=/path/to/key.pem
INGEST_TLS_CA=/path/to/ca.pem    # optional — enables mTLS client verification
```
Without `INGEST_TLS_CERT`, the TCP listener is silently skipped (dev mode).

## Terraform (infra/)
```bash
cd infra
terraform init
terraform workspace select prod   # or dev / staging
terraform plan -var="postgres_admin_password=$PG_PASSWORD"
terraform apply
```
State is stored in Azure Blob (`sentinel-tfstate-rg / sentineltfstate / tfstate/sentinel.tfstate`).

## Key Conventions
- All timestamps in UTC.
- Pydantic v2 throughout.
- Async SQLAlchemy 2.0.
- No synchronous DB calls in async context.
- Type hints on all functions.
- Use `structlog` for logging — never `print()`.
- Use `httpx.AsyncClient` — never synchronous HTTP clients.
- `ALLOWED_COLUMNS` frozenset guards all dynamic SQL column names.

## Do Not
- Do not hardcode secrets. Use environment variables loaded via `python-dotenv` in dev
  and Azure Key Vault references in production.
- Do not bypass `ALLOWED_COLUMNS` — it prevents SQL injection in the correlation engine.
- Do not add synchronous sleep() in async functions — use `asyncio.sleep()`.
- Do not call `alembic downgrade` in production without a tested rollback plan.

## Environment Variables (dev — copy .env.example to .env)
- `DATABASE_URL` — PostgreSQL async connection string (`postgresql+asyncpg://...`)
- `REDIS_URL` — Redis connection string
- `AZURE_STORAGE_ACCOUNT` / `AZURE_STORAGE_KEY` — Blob Storage
- `AZURE_STORAGE_CONTAINER` — defaults to `sentinel-raw`
- `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` — Azure AD
- `INGEST_HOST` / `INGEST_UDP_PORT` / `INGEST_TCP_PORT` / `INGEST_API_PORT`
- `INGEST_TLS_CERT` / `INGEST_TLS_KEY` / `INGEST_TLS_CA` — TLS syslog
- `GEOIP_DB_PATH` — MaxMind GeoLite2 mmdb file
- `CORS_ORIGINS` — comma-separated allowed origins for the API
- `LOG_LEVEL` — INFO (default) or DEBUG
- `INGEST_NODE_NAME` — identifies the ingest node in events
