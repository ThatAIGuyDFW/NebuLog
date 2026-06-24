"""Sentinel REST API — FastAPI application factory.

Mounts all routers, configures CORS and audit-logging middleware, and
exposes a /health endpoint.  Deployed as an Azure Container App.

Run locally:
    uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from api.auth import DEV_MODE
from api.db import audit_pool, close_audit_pool, engine, init_audit_pool
from api.routers import alerts, compliance, dashboard, events, rules, sources

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# CORS origins — tighten in production
# ---------------------------------------------------------------------------
_CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173"  # Vite dev server
).split(",")


# ---------------------------------------------------------------------------
# Lifespan — runs startup / shutdown logic
# ---------------------------------------------------------------------------

async def _run_migrations() -> None:
    """Run Alembic migrations to head on startup (idempotent)."""
    import sys
    from pathlib import Path
    from alembic.config import Config
    from alembic import command as alembic_command

    # Works from both the source tree and a PyInstaller frozen bundle.
    db_dir = Path(__file__).parent.parent / "db"
    if not db_dir.is_dir():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            db_dir = Path(meipass) / "db"

    try:
        cfg = Config(str(db_dir / "alembic.ini"))
        cfg.set_main_option("script_location", str(db_dir))
        # alembic.ini sets `version_locations = versions` (relative), which
        # resolves against the process CWD (DATA_DIR), not the bundle — so the
        # migration scripts are never found and nothing is applied.  Pin it to
        # the absolute path inside the bundle.
        cfg.set_main_option("version_locations", str(db_dir / "versions"))
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, alembic_command.upgrade, cfg, "head")
        log.info("migrations_complete", script_location=str(db_dir))
    except Exception as exc:
        log.error("migrations_error", exc=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer() if DEV_MODE else structlog.processors.JSONRenderer(),
        ]
    )
    # Auto-migrate on startup — safe to run on every start (Alembic is idempotent)
    await _run_migrations()
    try:
        await init_audit_pool()
    except Exception as exc:
        # Audit pool is optional — API starts without it (logs a warning)
        log.warning("audit_pool_unavailable", exc=str(exc))
    log.info("sentinel_api_started", dev_mode=DEV_MODE)
    yield
    await close_audit_pool()
    try:
        await engine.dispose()
    except Exception:
        pass
    log.info("sentinel_api_shutdown")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sentinel SIEM API",
    version="1.0.0",
    description=(
        "Sentinel Hybrid SIEM — ingest, alert, and compliance API. "
        "Authenticate with a valid Azure AD Bearer token."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Audit logging middleware
# ---------------------------------------------------------------------------

_SKIP_AUDIT_PREFIXES = ("/health", "/docs", "/redoc", "/openapi")


@app.middleware("http")
async def audit_middleware(request: Request, call_next) -> Response:
    start = time.perf_counter()
    response: Response = await call_next(request)
    duration_ms = int((time.perf_counter() - start) * 1000)

    path = request.url.path
    if any(path.startswith(p) for p in _SKIP_AUDIT_PREFIXES):
        return response

    user = getattr(request.state, "user", None)
    user_email = user.email if user else None
    source_ip = request.client.host if request.client else None

    # Fire-and-forget: never block the response for audit I/O
    asyncio.create_task(
        _write_audit_log(
            user_email=user_email,
            action=f"{request.method} {path}",
            source_ip=source_ip,
            response_status=response.status_code,
        )
    )
    log.debug("request", method=request.method, path=path,
              status=response.status_code, ms=duration_ms, user=user_email)
    return response


async def _write_audit_log(
    user_email: str | None,
    action: str,
    source_ip: str | None,
    response_status: int,
) -> None:
    if audit_pool is None:
        return
    try:
        async with audit_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_log (user_email, action, source_ip, response_status)
                VALUES ($1, $2, $3, $4)
                """,
                user_email, action, source_ip, response_status,
            )
    except Exception as exc:
        log.error("audit_log_write_failed", exc=str(exc))


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": str(exc.body)},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=request.url.path, exc=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Health"], include_in_schema=False)
async def health(request: Request) -> JSONResponse:
    from sqlalchemy import text
    from api.db import SessionLocal
    db_ok = False
    try:
        async with SessionLocal() as s:
            await s.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    code = status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=code,
        content={
            "status": "ok" if db_ok else "degraded",
            "database": "up" if db_ok else "down",
            "dev_mode": DEV_MODE,
        },
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
# When the pre-built UI is served from this same process (installer bundle),
# there is no reverse proxy to strip an /api prefix, and the UI calls /api/*
# (its default VITE_API_BASE_URL).  Mount the routers under /api in that case.
# In a proxied deployment (Azure) UI_DIST_PATH is unset, so routers stay at root
# and the ingress is responsible for the /api → root rewrite.
# ---------------------------------------------------------------------------
_UI_DIST = os.getenv("UI_DIST_PATH", "")
_BUNDLED_UI = bool(_UI_DIST) and Path(_UI_DIST).is_dir()
_API_PREFIX = "/api" if _BUNDLED_UI else ""

for _router in (events.router, alerts.router, rules.router,
                sources.router, dashboard.router, compliance.router):
    app.include_router(_router, prefix=_API_PREFIX)

# ---------------------------------------------------------------------------
# Static UI — served from the pre-built React bundle when running from the
# installer bundle.  UI_DIST_PATH is set by the launcher's .env.  A catch-all
# route serves real files when they exist and otherwise falls back to
# index.html so client-side routes (deep links / reloads) work.
# ---------------------------------------------------------------------------
if _BUNDLED_UI:
    _UI_ROOT = Path(_UI_DIST)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa_fallback(full_path: str) -> FileResponse:
        candidate = _UI_ROOT / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(_UI_ROOT / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        log_level="info",
    )
