"""Async database session management.

Provides:
  - `engine`        — SQLAlchemy async engine (shared across the app)
  - `get_db()`      — FastAPI dependency yielding an AsyncSession per request
  - `audit_pool`    — raw asyncpg pool for fire-and-forget audit_log inserts
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import asyncpg
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://sentinel:sentinel_dev@localhost:5432/sentinel",
)

engine = create_async_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# Separate raw asyncpg pool used only for audit_log writes (avoids
# mixing audit I/O with the SQLAlchemy session lifecycle)
audit_pool: asyncpg.Pool | None = None


async def init_audit_pool() -> None:
    global audit_pool
    dsn = DATABASE_URL.replace("+asyncpg", "")
    audit_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)


async def close_audit_pool() -> None:
    if audit_pool is not None:
        await audit_pool.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async SQLAlchemy session per request."""
    async with SessionLocal() as session:
        yield session


class Base(DeclarativeBase):
    pass
