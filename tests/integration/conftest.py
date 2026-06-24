"""pytest fixtures for integration tests.

Integration tests require Docker services to be running:
    docker compose up -d postgres redis

They are skipped automatically if the services are unreachable.
Run with:
    pytest tests/integration/ -v -m integration
"""

import asyncio
import os

import pytest
import pytest_asyncio

# Load .env so tests pick up DATABASE_URL / REDIS_URL
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel_dev@localhost:5432/sentinel")


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires running Docker services")


async def _check_redis() -> bool:
    try:
        from redis.asyncio import from_url
        r = from_url(REDIS_URL)
        await r.ping()
        await r.aclose()
        return True
    except Exception:
        return False


async def _check_postgres() -> bool:
    try:
        import asyncpg
        conn = await asyncpg.connect(DATABASE_URL.replace("+asyncpg", ""))
        await conn.execute("SELECT 1")
        await conn.close()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def redis_available():
    ok = await _check_redis()
    if not ok:
        pytest.skip("Redis not reachable — run: docker compose up -d redis")
    return REDIS_URL


@pytest_asyncio.fixture(scope="session")
async def postgres_available():
    ok = await _check_postgres()
    if not ok:
        pytest.skip("PostgreSQL not reachable — run: docker compose up -d postgres")
    return DATABASE_URL.replace("+asyncpg", "")


@pytest_asyncio.fixture(scope="session")
async def db_conn(postgres_available):
    import asyncpg
    conn = await asyncpg.connect(postgres_available)
    yield conn
    await conn.close()


@pytest_asyncio.fixture(scope="session")
async def redis_client(redis_available):
    from redis.asyncio import from_url
    r = from_url(redis_available, decode_responses=True)
    yield r
    await r.aclose()
