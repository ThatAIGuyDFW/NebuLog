# Sentinel SIEM — Architecture

## Overview

Sentinel is a compliance-grade hybrid SIEM and log intelligence platform built
for Nebula Networking.  It ingests logs from FortiGate, Cisco ASA, Windows
Event Log, and Linux syslog/journald; enriches and stores them in PostgreSQL;
archives raw logs to Azure Blob Storage; and surfaces events, alerts, and
compliance reports through a FastAPI REST API and React web UI.

---

## Component Map

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
│    PostgreSQL        │  │  • Filesystem fallback │
└─────────────────────┘  └───────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────────────┐
│  PostgreSQL 16  (via Azure Flexible Server in prod)               │
│  • events table — RANGE partitioned by received_at (monthly)     │
│  • pgvector extension (future semantic search)                   │
│  • alert_rules, alerts, sources, blacklists, audit_log           │
│  • Alembic migrations — auto-applied on API startup              │
└──────────────────────────┬───────────────────────────────────────┘
                           │
              ┌────────────┴──────────────┐
              ▼                           ▼
┌─────────────────────┐    ┌────────────────────────────────────┐
│  Correlation Engine │    │  REST API  (api/)                  │
│  (correlation/)     │    │  FastAPI on port 8000              │
│  APScheduler ticks: │    │  • Azure AD JWT auth (PKCE + CC)  │
│  • 30s: threshold,  │    │  • RBAC: Admin / Analyst / RO     │
│    blacklist, seq   │    │  • Routers: events, alerts, rules, │
│  • 5min: absence,   │    │    sources, dashboard, compliance  │
│    anomaly          │    │  • GET /events/{id}/verify (SHA-256│
│  Alert dedup by     │    │    tamper detection)               │
│  rule_id+group_key  │    │  • Audit log (asyncpg pool)        │
└─────────────────────┘    └──────────────┬─────────────────────┘
                                          │ HTTPS
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

---

## Data Flow

```
Raw syslog/JSON
    → Ingest (parse + SHA-256 stamp)
    → Redis events:normalized
    → Storage Worker (GeoIP + compliance tags)
    → PostgreSQL events table
    → Correlation Engine (SQL queries every 30s/5min)
    → alerts table (upsert by rule_id+group_key)
    → API → UI

Raw bytes
    → Redis events:raw
    → Archive Worker (gzip NDJSON)
    → Azure Blob Storage (WORM)
```

---

## Parsers

| Source | Format | Parser |
|---|---|---|
| FortiGate | Extended syslog key=value | `ingest/parsers/fortigate.py` |
| Cisco ASA | BSD syslog + %ASA-sev-mnem | `ingest/parsers/cisco_asa.py` |
| Windows | JSON (EventID, EventData) | `ingest/parsers/windows.py` |
| Linux | journald JSON / rsyslog JSON | `ingest/parsers/linux.py` |

All parsers emit a `NormalizedEvent` (Pydantic v2) with UTC timestamps,
GeoIP coordinates, and HIPAA/PCI compliance tags applied by `workers/compliance.py`.

---

## Correlation Rule Types

| Type | Trigger | SQL approach |
|---|---|---|
| `threshold` | N events from same group_by in window | `COUNT(*) HAVING >= N` |
| `sequence` | Step A then step B from same group_by | CTE chain with ordered JOINs |
| `absence` | Zero matching events in window | `COUNT(*) = 0` |
| `blacklist` | Field value in named blacklist table | `JOIN blacklists` |
| `anomaly` | Count > mean + Z×stddev vs baseline | `STDDEV_POP` over hourly buckets |

SQL injection is prevented by `ALLOWED_COLUMNS` whitelist for all dynamic column names.

---

## Security Controls

| Control | Implementation |
|---|---|
| No hardcoded secrets | All secrets via env vars / Azure Key Vault |
| Auth | Azure AD JWT RS256; PKCE for SPA; client-credentials for agents |
| RBAC | `Sentinel.Admin`, `Sentinel.Analyst`, `Sentinel.ReadOnly` |
| Audit log | Every non-health API request logged to `audit_log` table |
| SQL injection | `ALLOWED_COLUMNS` whitelist; SQLAlchemy ORM parameterized queries |
| Rate limiting | Token bucket per source IP (10k ev/s); eviction prevents memory exhaustion |
| Tamper detection | SHA-256 of raw_message stored at ingest; `GET /events/{id}/verify` |
| TLS | TCP 6514 (RFC 5425); enforced TLS 1.2+ minimum |
| WORM archival | Azure Blob immutability policy; GRS replication |
| Compliance retention | HIPAA: 2192-day lifecycle; PCI DSS: 365-day hot tier |

---

## Compliance Mapping

| Requirement | Control |
|---|---|
| HIPAA § 164.312(b) — Audit controls | `audit_log` table; all API access logged |
| HIPAA § 164.312(c)(1) — Integrity | SHA-256 `raw_hash`; `GET /events/{id}/verify` |
| HIPAA 6-year retention | Azure lifecycle policy `retention_days_cold = 2192` |
| PCI DSS 10.3 — Protect audit logs | WORM immutability; `NoDelete` lock |
| PCI DSS 10.5 — Retain 12 months hot | `retention_days_hot = 365` lifecycle tier |
| PCI DSS 10.6 — Review daily | `GET /compliance/report?framework=pci_dss` daily gap check |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 (backend), TypeScript (UI) |
| Web framework | FastAPI + uvicorn |
| ORM / migrations | SQLAlchemy 2.0 async + Alembic (auto-run on startup) |
| Database | PostgreSQL 16 with pgvector, pg_partman |
| Queue | Redis 7 Streams with consumer groups |
| Scheduling | APScheduler AsyncIOScheduler |
| GeoIP | MaxMind GeoLite2 |
| Cloud storage | Azure Blob Storage (GRS, WORM) |
| Auth | Azure AD / Entra ID (MSAL) |
| Infrastructure | Terraform ≥ 1.7, Azure provider ~3.110 |
| UI | React 18 + Vite 5 + TailwindCSS + Recharts + TanStack |
| Agents | Python (pywin32 for Windows, journalctl/syslog for Linux) |

---

## Directory Structure

```
sentinel/
├── agents/
│   ├── windows/        # Windows Event Log agent (pywin32)
│   └── linux/          # journald / syslog tail agent + systemd unit
├── api/
│   ├── models/         # SQLAlchemy ORM + Pydantic v2 schemas
│   ├── routers/        # events, alerts, rules, sources, dashboard, compliance
│   ├── auth.py         # Azure AD JWT validation + RBAC
│   ├── db.py           # async engine + audit asyncpg pool
│   └── main.py         # FastAPI app + lifespan (auto-migration)
├── correlation/
│   ├── evaluators/     # threshold, sequence, absence, blacklist, anomaly
│   ├── engine.py       # APScheduler + alert upsert deduplication
│   └── rule_dsl.py     # Pydantic v2 rule body schemas
├── db/
│   ├── versions/       # Alembic migrations (0001–0003)
│   └── env.py          # strips +asyncpg for sync Alembic runs
├── infra/
│   ├── main.tf         # Root module: resource group, modules wiring
│   ├── variables.tf
│   └── modules/
│       ├── storage/    # Azure Blob Storage + WORM lifecycle
│       ├── postgres/   # PostgreSQL Flexible Server + pgvector
│       ├── networking/ # VNet, subnets, NSG rules (514/6514/8001)
│       └── ad_app/     # Azure AD app registration + 3 roles
├── ingest/
│   ├── parsers/        # fortigate, cisco_asa, windows, linux
│   ├── main.py         # UDP 514 + TLS TCP 6514 + FastAPI 8001
│   ├── tls_listener.py # RFC 5425 octet-count + newline framing
│   ├── rate_limiter.py # Token bucket (eviction + structured drop logs)
│   ├── publisher.py    # Redis Streams publisher
│   └── source_registry.py
├── tests/
│   ├── parsers/        # 100+ parser unit tests
│   ├── integration/    # Docker-dependent pipeline tests
│   ├── test_api.py     # 33 API tests
│   ├── test_correlation.py  # 38 correlation tests
│   └── test_agents.py  # 25 agent tests
├── ui/                 # React SPA (see ui/src/)
└── workers/
    ├── storage_worker.py   # PostgreSQL batch insert
    └── archive_worker.py   # Azure Blob archive
```
