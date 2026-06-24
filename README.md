# NebuLog — Sentinel SIEM

**Hybrid SIEM & Log Intelligence Platform by Nebula Networking**

Compliance-grade security event management with on-premises log ingest, Azure cloud storage, a FastAPI REST API, React UI, and a built-in correlation engine. Supports HIPAA and PCI DSS v4.0.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Repository Layout](#repository-layout)
4. [Local Development Setup](#local-development-setup)
5. [Running the Services](#running-the-services)
6. [Windows Agent Setup](#windows-agent-setup)
7. [Linux Agent Setup](#linux-agent-setup)
8. [Configuring Log Sources](#configuring-log-sources)
9. [TLS Syslog (TCP 6514)](#tls-syslog-tcp-6514)
10. [Production Deployment on Azure](#production-deployment-on-azure)
11. [Azure AD Authentication](#azure-ad-authentication)
12. [Verifying the Installation](#verifying-the-installation)
13. [Environment Variable Reference](#environment-variable-reference)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  Log Sources                                                      │
│  FortiGate · Cisco ASA · Windows hosts · Linux hosts             │
└───────────────────────┬──────────────────────────────────────────┘
                        │ UDP 514  /  TLS TCP 6514  /  HTTPS 8001
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Ingest Service  (ingest/)                                        │
│  • UDP DatagramProtocol (asyncio)  — FortiGate, Cisco ASA        │
│  • TLS TCP Protocol  (RFC 5425)    — encrypted syslog            │
│  • FastAPI POST /ingest            — Windows & Linux agents      │
│  • Per-IP token-bucket rate limiter (eviction, drop logging)     │
│  • SHA-256 hash stamped on every raw message at ingest           │
│  • Publishes to Redis Streams: events:normalized / events:raw    │
└───────────────────────┬──────────────────────────────────────────┘
                        │ Redis Streams (consumer groups)
              ┌─────────┴──────────┐
              ▼                    ▼
┌─────────────────────┐  ┌───────────────────────┐
│  Storage Worker     │  │  Archive Worker        │
│  (workers/)         │  │  (workers/)            │
│  • GeoIP enrichment │  │  • gzip NDJSON batches │
│  • Compliance tags  │  │  • Azure Blob upload   │
│  • 500-row batch    │  │    raw/{type}/{date}/  │
│    INSERT →         │  │  • WORM immutability   │
│    PostgreSQL       │  │  • Filesystem fallback │
└─────────────────────┘  └───────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────────────┐
│  PostgreSQL 16  (via Azure Flexible Server in prod)              │
│  • events table — RANGE partitioned by received_at (monthly)    │
│  • pgvector extension (future semantic search)                   │
│  • alert_rules, alerts, sources, blacklists, audit_log           │
│  • Alembic migrations — auto-applied on API startup              │
└──────────────────────┬───────────────────────────────────────────┘
                       │
              ┌────────┴──────────────┐
              ▼                       ▼
┌─────────────────────┐    ┌────────────────────────────────────┐
│  Correlation Engine │    │  REST API  (api/)                  │
│  (correlation/)     │    │  FastAPI on port 8000              │
│  APScheduler ticks: │    │  • Azure AD JWT auth (PKCE + CC)  │
│  • 30s: threshold,  │    │  • RBAC: Admin / Analyst / RO     │
│    blacklist, seq   │    │  • Routers: events, alerts, rules, │
│  • 5min: absence,   │    │    sources, dashboard, compliance  │
│    anomaly          │    │  • GET /events/{id}/verify         │
│  Alert dedup by     │    │  • Audit log (asyncpg pool)        │
│  rule_id+group_key  │    └──────────────┬─────────────────────┘
└─────────────────────┘                   │ HTTPS
                                          ▼
                           ┌────────────────────────────────────┐
                           │  React UI  (ui/)                   │
                           │  Vite 5 · TailwindCSS · Recharts   │
                           │  TanStack Query / Table · MSAL     │
                           │  • Dashboard (timeline, charts)    │
                           │  • Events explorer (10 filters)    │
                           │  • Alerts list + detail + patch    │
                           │  • Rules CRUD (Admin only)         │
                           │  • Sources + enable/disable        │
                           │  • Compliance report (HIPAA/PCI)   │
                           └────────────────────────────────────┘
```

### Supported Log Sources

| Source | Format | Protocol |
|---|---|---|
| FortiGate | Extended syslog key=value | UDP 514 / TLS TCP 6514 |
| Cisco ASA | BSD syslog + %ASA-sev-mnem | UDP 514 / TLS TCP 6514 |
| Windows hosts | JSON (EventID, EventData) | HTTPS agent batch |
| Linux hosts | journald JSON / rsyslog JSON | HTTPS agent batch |

### Correlation Rule Types

| Type | Trigger |
|---|---|
| `threshold` | N events from the same group within a window |
| `sequence` | Step A then step B from the same group |
| `absence` | Zero matching events in a window |
| `blacklist` | Field value matches a named blacklist |
| `anomaly` | Count exceeds mean + Z×stddev vs. baseline |

---

## Prerequisites

### Required on the server running Sentinel

| Software | Minimum Version | Notes |
|---|---|---|
| Python | 3.12 | All backend services |
| Node.js | 20 LTS | UI build only |
| Docker Desktop | 4.x | Local dev (Redis + PostgreSQL) |
| Docker Compose | v2 (plugin) | Bundled with Docker Desktop |
| Git | any | |

### Required for production

| Software | Purpose |
|---|---|
| Terraform | ≥ 1.7 — provisions Azure infrastructure |
| Azure CLI (`az`) | Authenticating Terraform and managing resources |
| OpenSSL | Generating TLS certificates for syslog TCP 6514 |
| MaxMind GeoLite2 | GeoIP enrichment (free registration at maxmind.com) |

### Azure (production only)

- Azure subscription with Contributor rights
- Permissions to register an Azure AD application (Application Administrator role)
- A storage account for Terraform remote state (created once manually — see [Production Deployment](#production-deployment-on-azure))

---

## Repository Layout

```
sentinel/
├── agents/
│   ├── windows/        Windows Event Log agent (pywin32)
│   └── linux/          journald / syslog tail agent + systemd unit
├── api/
│   ├── models/         SQLAlchemy ORM + Pydantic v2 schemas
│   ├── routers/        events, alerts, rules, sources, dashboard, compliance
│   ├── auth.py         Azure AD JWT validation + RBAC
│   ├── db.py           async engine + audit asyncpg pool
│   └── main.py         FastAPI app + lifespan (auto-migration)
├── correlation/
│   ├── evaluators/     threshold, sequence, absence, blacklist, anomaly
│   ├── engine.py       APScheduler + alert upsert deduplication
│   └── rule_dsl.py     Pydantic v2 rule body schemas
├── db/
│   ├── versions/       Alembic migrations (0001–0003)
│   └── env.py          strips +asyncpg for sync Alembic runs
├── infra/
│   └── modules/
│       ├── storage/    Azure Blob Storage + WORM lifecycle
│       ├── postgres/   PostgreSQL Flexible Server + pgvector
│       ├── networking/ VNet, subnets, NSG rules (514/6514/8001)
│       └── ad_app/     Azure AD app registration + 3 roles
├── ingest/
│   ├── parsers/        fortigate, cisco_asa, windows, linux
│   ├── tls_listener.py RFC 5425 octet-count + newline framing
│   ├── rate_limiter.py token bucket (eviction + drop logs)
│   └── main.py         UDP 514 + TLS TCP 6514 + FastAPI 8001
├── tests/              229 unit and integration tests
├── ui/                 React 18 SPA
├── workers/
│   ├── storage_worker.py   PostgreSQL batch insert
│   └── archive_worker.py   Azure Blob archive
├── docker-compose.yml  Local dev: Redis 7 + PostgreSQL 16
└── .env.example        Environment variable template
```

---

## Local Development Setup

### 1. Create the Python virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements-dev.txt
pip install -r api/requirements.txt
pip install -r ingest/requirements.txt
pip install -r workers/requirements.txt
pip install -r correlation/requirements.txt
```

### 2. Copy and edit the environment file

```bash
cp .env.example .env
```

Minimum values for local dev:

```env
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel_dev@localhost:5432/sentinel
REDIS_URL=redis://localhost:6379/0

# Leave blank — auth is bypassed and Azure storage falls back to local filesystem
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_STORAGE_ACCOUNT=
AZURE_STORAGE_KEY=
AZURE_STORAGE_CONTAINER=sentinel-raw

INGEST_HOST=0.0.0.0
INGEST_UDP_PORT=514
INGEST_TCP_PORT=6514
INGEST_API_PORT=8001

# Download GeoLite2-City.mmdb from maxmind.com and set the path
GEOIP_DB_PATH=/opt/geoip/GeoLite2-City.mmdb

LOG_LEVEL=INFO
INGEST_NODE_NAME=ingest-01
```

> **Dev-mode shortcuts:** When `AZURE_TENANT_ID` is blank, the API returns a synthetic admin user — no login required. When Azure Storage credentials are absent, the archive worker writes to a local `./archive/` directory instead.

### 3. Start Redis and PostgreSQL

```bash
docker compose up -d

# Verify both are healthy
docker compose ps
```

### 4. Apply database migrations

Migrations run automatically on API startup, but you can also run them manually:

```bash
cd db
alembic upgrade head
cd ..
```

This creates all tables, partitions, indexes, and seeds 12 default correlation rules.

### 5. Install UI dependencies

```bash
cd ui
npm install
cd ..
```

---

## Running the Services

Open a separate terminal for each service with the virtual environment activated.

| Terminal | Command | Port |
|---|---|---|
| Ingest | `python -m ingest.main` | UDP 514, TCP 6514, HTTP 8001 |
| API | `uvicorn api.main:app --reload --port 8000` | 8000 |
| Storage worker | `python -m workers.storage_worker` | — |
| Archive worker | `python -m workers.archive_worker` | — |
| Correlation engine | `python -m correlation.engine` | — |
| UI | `cd ui && npm run dev` | 3000 |

The web interface is available at **http://localhost:3000**.  
API docs (Swagger) are at **http://localhost:8000/docs**.

### Run the test suite

```bash
# Unit tests — no Docker required
pytest tests/ --ignore=tests/integration -v

# Integration tests — requires docker compose up -d
pytest tests/integration/ -v -m integration
```

---

## Windows Agent Setup

The Windows agent collects events from the Windows Event Log and ships them to the ingest service.

### 1. Install dependencies (Administrator PowerShell)

```powershell
cd agents\windows
pip install -r requirements.txt

# pywin32 post-install step (required)
python Scripts\pywin32_postinstall.py -install
```

### 2. Configure

```powershell
copy .env.example .env
notepad .env
```

Key values:

```env
SENTINEL_INGEST_URL=http://localhost:8001   # or https:// in production
SENTINEL_API_TOKEN=                          # set in production
SENTINEL_VERIFY_TLS=false                    # true in production
SENTINEL_CHANNELS=Security,System,Application
SENTINEL_BATCH_SIZE=200
SENTINEL_POLL_INTERVAL=5
SENTINEL_CHECKPOINT_DIR=C:\ProgramData\Sentinel\checkpoints
```

### 3. Run in the foreground (test)

```powershell
python agent.py
```

### 4. Install as a Windows Service (production)

```powershell
# Run as Administrator
python service.py install
python service.py start

Get-Service SentinelAgent
```

To stop or remove:

```powershell
python service.py stop
python service.py remove
```

---

## Linux Agent Setup

### 1. Install

```bash
sudo useradd -r -s /sbin/nologin sentinel
sudo mkdir -p /opt/sentinel-agent
sudo cp -r agents/linux/* /opt/sentinel-agent/

python3 -m venv /opt/sentinel-agent/venv
/opt/sentinel-agent/venv/bin/pip install -r /opt/sentinel-agent/requirements.txt

sudo mkdir -p /var/lib/sentinel
sudo chown sentinel:sentinel /var/lib/sentinel
```

### 2. Configure

```bash
sudo cp /opt/sentinel-agent/.env.example /opt/sentinel-agent/.env
sudo nano /opt/sentinel-agent/.env
```

```env
SENTINEL_INGEST_URL=https://your-ingest-server:8001
SENTINEL_API_TOKEN=
SENTINEL_VERIFY_TLS=true
SENTINEL_MODE=journald        # or "syslog" for file tail
SENTINEL_UNITS=sshd,sudo,cron,kernel,audit
SENTINEL_BATCH_SIZE=200
SENTINEL_POLL_INTERVAL=5
SENTINEL_CHECKPOINT_DIR=/var/lib/sentinel
```

### 3. Install the systemd unit

```bash
sudo cp /opt/sentinel-agent/sentinel-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-agent

sudo systemctl status sentinel-agent
sudo journalctl -u sentinel-agent -f
```

---

## Configuring Log Sources

All sources must be registered before events are parsed and stored.

### Via the Web UI

1. Open **http://localhost:3000 → Sources**
2. Click **+ Add Source**
3. Enter the source IP, type, hostname, and label
4. Click **Register**

### Via the API

```bash
curl -X POST http://localhost:8000/sources \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.1",
    "source_type": "fortigate",
    "hostname": "fw-core-01",
    "label": "Core Firewall"
  }'
```

### FortiGate syslog configuration

```
config log syslogd setting
    set status enable
    set server <ingest-server-ip>
    set port 514
    set format default
end
```

### Cisco ASA syslog configuration

```
logging enable
logging host inside <ingest-server-ip>
logging trap informational
logging facility 23
```

---

## TLS Syslog (TCP 6514)

Encrypted syslog for traffic traversing untrusted networks.

### 1. Generate a self-signed certificate (dev/testing)

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout ingest-key.pem -out ingest-cert.pem \
  -days 365 -nodes \
  -subj "/CN=sentinel-ingest"
```

For production, use a certificate from your internal CA or Let's Encrypt.

### 2. Enable in the ingest service

Add to `.env`:

```env
INGEST_TLS_CERT=/path/to/ingest-cert.pem
INGEST_TLS_KEY=/path/to/ingest-key.pem
INGEST_TLS_CA=/path/to/ca.pem    # optional — enables mTLS client verification
```

Restart the ingest service. You will see `tls_listener_ready host=0.0.0.0 port=6514` in the logs.

### 3. Configure FortiGate to use TLS syslog

```
config log syslogd setting
    set status enable
    set server <ingest-server-ip>
    set port 6514
    set mode reliable
    set enc-algorithm high
end
```

Without `INGEST_TLS_CERT` set, the TCP listener is silently skipped (dev mode). UDP 514 is always active.

---

## Production Deployment on Azure

### 1. One-time Terraform state bootstrap

```bash
az group create --name sentinel-tfstate-rg --location eastus2

az storage account create \
  --name sentineltfstate \
  --resource-group sentinel-tfstate-rg \
  --sku Standard_LRS \
  --min-tls-version TLS1_2

az storage container create \
  --name tfstate \
  --account-name sentineltfstate
```

### 2. Provision Azure infrastructure

```bash
cd infra
terraform init

terraform workspace new prod
terraform workspace select prod

terraform plan \
  -var="environment=prod" \
  -var="postgres_admin_password=$PG_ADMIN_PASSWORD" \
  -var="location=eastus2" \
  -out=tfplan

terraform apply tfplan
```

This provisions:
- Resource group `sentinel-prod-rg`
- VNet with ingest, API, and database subnets + NSG rules
- PostgreSQL 16 Flexible Server (ZoneRedundant HA) with pgvector
- Azure Blob Storage (GRS, WORM immutability, lifecycle tiers)
- Azure AD app registration with Admin/Analyst/ReadOnly roles

### 3. Capture outputs

```bash
terraform output -raw postgres_connection_string
terraform output -raw storage_connection_string
terraform output azure_client_id
terraform output azure_tenant_id
```

### 4. Populate production `.env`

```env
DATABASE_URL=<from terraform output>

AZURE_TENANT_ID=<from terraform output>
AZURE_CLIENT_ID=<from terraform output>
AZURE_CLIENT_SECRET=<from Key Vault>

AZURE_STORAGE_ACCOUNT=<from terraform output>
AZURE_STORAGE_KEY=<from Key Vault>
AZURE_STORAGE_CONTAINER=sentinel-raw

INGEST_TLS_CERT=/etc/sentinel/tls/cert.pem
INGEST_TLS_KEY=/etc/sentinel/tls/key.pem
```

---

## Azure AD Authentication

Terraform's `ad_app` module creates three roles:

| Role | Permissions |
|---|---|
| `Sentinel.Admin` | Full access — CRUD rules, manage sources, view all data |
| `Sentinel.Analyst` | Read all data, acknowledge/close alerts |
| `Sentinel.ReadOnly` | Read events, alerts, and dashboard only |

### Assign users to roles

1. Azure Portal → **Azure Active Directory → Enterprise Applications**
2. Find **Sentinel SIEM (prod)**
3. **Users and groups → Add user/group**
4. Assign to the appropriate app role

### Configure the UI for Azure AD

```env
# ui/.env
VITE_AZURE_TENANT_ID=<your-tenant-id>
VITE_AZURE_CLIENT_ID=<your-client-id>
```

Then rebuild: `cd ui && npm run build`

### Dev mode (no Azure AD)

Leave `VITE_AZURE_TENANT_ID` and server-side `AZURE_TENANT_ID` blank. The UI will not show a login screen and the API accepts all requests as a synthetic admin.

---

## Verifying the Installation

### Health checks

```bash
curl http://localhost:8001/health   # ingest
curl http://localhost:8000/health   # API
```

Expected: `{"status": "ok", ...}`

### Send a test syslog message

```bash
# FortiGate-style (UDP)
echo '<134>date=2024-01-15 time=10:23:45 devname=fw01 type=traffic subtype=forward action=accept srcip=10.0.0.1 dstip=8.8.8.8 srcport=51234 dstport=443 proto=6 sentbyte=1024 rcvdbyte=2048' \
  | nc -u localhost 514
```

### Send a test agent batch

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-Source-Type: linux" \
  -H "Content-Type: application/json" \
  -d '[{
    "__REALTIME_TIMESTAMP": "1705311825000000",
    "_HOSTNAME": "test-server",
    "_COMM": "sshd",
    "MESSAGE": "Accepted publickey for jsmith from 10.0.0.1 port 22 ssh2",
    "PRIORITY": "6"
  }]'
```

Expected: `{"accepted": 1, "errors": 0}`

### Verify SHA-256 tamper detection

```bash
# Get a recent event ID
curl "http://localhost:8000/events?page_size=1"

# Verify its integrity
curl "http://localhost:8000/events/<event-id>/verify"
# {"intact": true, "event_id": "...", "stored_hash": "...", "recomputed_hash": "..."}
```

### Confirm correlation rules loaded

```bash
curl http://localhost:8000/rules
# Returns 12 pre-seeded rules (brute force, port scan, privilege escalation, etc.)
```

---

## Environment Variable Reference

### Core services (`.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | PostgreSQL async connection string (`postgresql+asyncpg://...`) |
| `REDIS_URL` | Yes | `redis://localhost:6379/0` | Redis connection string |
| `AZURE_TENANT_ID` | Prod only | — | Azure AD tenant ID; blank = dev mode (no auth) |
| `AZURE_CLIENT_ID` | Prod only | — | Azure AD application client ID |
| `AZURE_CLIENT_SECRET` | Prod only | — | Azure AD client secret |
| `AZURE_STORAGE_ACCOUNT` | Prod only | — | Azure Blob Storage account name |
| `AZURE_STORAGE_KEY` | Prod only | — | Azure Blob Storage account key |
| `AZURE_STORAGE_CONTAINER` | No | `sentinel-raw` | Container for raw log archive |
| `INGEST_HOST` | No | `0.0.0.0` | Bind address for all ingest listeners |
| `INGEST_UDP_PORT` | No | `514` | UDP syslog port |
| `INGEST_TCP_PORT` | No | `6514` | TLS TCP syslog port |
| `INGEST_API_PORT` | No | `8001` | Agent HTTP ingest port |
| `INGEST_TLS_CERT` | TLS only | — | Path to TLS certificate PEM (enables TCP 6514) |
| `INGEST_TLS_KEY` | TLS only | — | Path to TLS private key PEM |
| `INGEST_TLS_CA` | mTLS only | — | Path to CA bundle (enables client cert verification) |
| `GEOIP_DB_PATH` | No | `/opt/geoip/GeoLite2-City.mmdb` | MaxMind GeoLite2 database path |
| `LOG_LEVEL` | No | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `INGEST_NODE_NAME` | No | `ingest-01` | Node identifier stamped on every event |
| `CORS_ORIGINS` | No | `http://localhost:3000` | Comma-separated allowed CORS origins |

### Windows agent (`agents/windows/.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `SENTINEL_INGEST_URL` | Yes | — | Full URL of the ingest service |
| `SENTINEL_API_TOKEN` | Prod only | — | Bearer token for authenticated ingest |
| `SENTINEL_VERIFY_TLS` | No | `true` | Set `false` only with self-signed certs in dev |
| `SENTINEL_CHANNELS` | No | `Security,System,Application` | Comma-separated Event Log channels |
| `SENTINEL_BATCH_SIZE` | No | `200` | Maximum events per HTTP POST |
| `SENTINEL_POLL_INTERVAL` | No | `5` | Seconds between polls |
| `SENTINEL_CHECKPOINT_DIR` | No | `C:\ProgramData\Sentinel\checkpoints` | Per-channel checkpoint files |

### Linux agent (`agents/linux/.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `SENTINEL_INGEST_URL` | Yes | — | Full URL of the ingest service |
| `SENTINEL_API_TOKEN` | Prod only | — | Bearer token for authenticated ingest |
| `SENTINEL_VERIFY_TLS` | No | `true` | Set `false` only with self-signed certs in dev |
| `SENTINEL_MODE` | No | `journald` | `journald` or `syslog` |
| `SENTINEL_UNITS` | No | all units | Comma-separated systemd units to filter |
| `SENTINEL_SYSLOG_PATH` | No | `/var/log/syslog` | Path to syslog file (mode=syslog only) |
| `SENTINEL_BATCH_SIZE` | No | `200` | Maximum events per HTTP POST |
| `SENTINEL_POLL_INTERVAL` | No | `5` | Seconds between polls |
| `SENTINEL_CHECKPOINT_DIR` | No | `/var/lib/sentinel` | Cursor/offset checkpoint files |

### UI (`ui/.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `VITE_AZURE_TENANT_ID` | Prod only | — | Azure AD tenant ID; blank = dev mode |
| `VITE_AZURE_CLIENT_ID` | Prod only | — | Azure AD application client ID |
| `VITE_API_BASE_URL` | Prod only | `/api` | API base URL |

### Port Summary

| Port | Protocol | Service |
|---|---|---|
| `514` | UDP | Syslog ingest (FortiGate, Cisco ASA) |
| `6514` | TCP/TLS | Encrypted syslog ingest |
| `8001` | HTTP/HTTPS | Agent batch ingest |
| `8000` | HTTP/HTTPS | REST API |
| `3000` | HTTP | React UI (dev server) |
| `5432` | TCP | PostgreSQL (internal) |
| `6379` | TCP | Redis (internal) |

---

## Compliance

| Requirement | Control |
|---|---|
| HIPAA § 164.312(b) — Audit controls | `audit_log` table; all API access logged |
| HIPAA § 164.312(c)(1) — Integrity | SHA-256 `raw_hash`; `GET /events/{id}/verify` |
| HIPAA 6-year retention | Azure lifecycle policy — 2,192-day cold tier |
| PCI DSS 10.3 — Protect audit logs | WORM immutability; `NoDelete` lock |
| PCI DSS 10.5 — Retain 12 months hot | 365-day hot tier lifecycle rule |
| PCI DSS 10.6 — Review daily | `GET /compliance/report?framework=pci_dss` |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 (backend), TypeScript (UI) |
| Web framework | FastAPI + uvicorn |
| ORM / migrations | SQLAlchemy 2.0 async + Alembic |
| Database | PostgreSQL 16 with pgvector, pg_partman |
| Queue | Redis 7 Streams with consumer groups |
| Scheduling | APScheduler AsyncIOScheduler |
| GeoIP | MaxMind GeoLite2 |
| Cloud storage | Azure Blob Storage (GRS, WORM) |
| Auth | Azure AD / Entra ID (MSAL) |
| Infrastructure | Terraform ≥ 1.7, Azure provider ~3.110 |
| UI | React 18 + Vite 5 + TailwindCSS + Recharts + TanStack |
| Agents | Python (pywin32 for Windows, journalctl/syslog for Linux) |
