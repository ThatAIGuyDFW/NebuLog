"""Azure AD / Entra ID JWT authentication and RBAC.

In production:
  - Validates Bearer tokens against the Azure AD JWKS endpoint
  - Extracts roles from the `roles` claim (Sentinel.Admin, Sentinel.Analyst,
    Sentinel.ReadOnly)

In dev mode (AZURE_TENANT_ID not set):
  - Accepts any Bearer value and returns a synthetic admin user
  - Allows the API to run without an Azure AD app registration

RBAC enforcement via require_roles() dependency factory:
  admin    — full access
  analyst  — read all + write alerts
  read_only — GET endpoints only
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable

import httpx
import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer, HTTPBearer, HTTPAuthorizationCredentials

log = structlog.get_logger()

TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
DEV_MODE: bool = not TENANT_ID

JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

# Role constants (as configured in Azure AD app registration)
ROLE_ADMIN = "Sentinel.Admin"
ROLE_ANALYST = "Sentinel.Analyst"
ROLE_READ_ONLY = "Sentinel.ReadOnly"

# Internal short names used by require_roles()
_ROLE_MAP = {
    "admin": ROLE_ADMIN,
    "analyst": ROLE_ANALYST,
    "read_only": ROLE_READ_ONLY,
}

_http_bearer = HTTPBearer(auto_error=False)


@dataclass
class TokenData:
    email: str
    roles: list[str] = field(default_factory=list)
    sub: str = ""

    def has_role(self, *roles: str) -> bool:
        for r in roles:
            full = _ROLE_MAP.get(r, r)
            if full in self.roles:
                return True
        return False


# ---------------------------------------------------------------------------
# JWKS cache — refresh every hour
# ---------------------------------------------------------------------------

_jwks_cache: dict = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0


async def _get_jwks() -> dict:
    global _jwks_cache, _jwks_fetched_at
    if time.time() - _jwks_fetched_at < _JWKS_TTL and _jwks_cache:
        return _jwks_cache
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(JWKS_URL)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_fetched_at = time.time()
    return _jwks_cache


def _decode_token(token: str, jwks: dict) -> dict:
    """Validate JWT and return claims. Raises ValueError on failure."""
    try:
        from jose import jwt, JWTError  # type: ignore
        from jose.exceptions import ExpiredSignatureError, JWTClaimsError  # type: ignore
    except ImportError:
        raise ValueError("python-jose not installed; run: pip install python-jose[cryptography]")

    try:
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
            options={"verify_at_hash": False},
        )
    except (JWTError, ExpiredSignatureError, JWTClaimsError) as exc:
        raise ValueError(str(exc))
    return claims


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_http_bearer),
) -> TokenData:
    """Validate the Bearer token and return the authenticated user.

    Sets `request.state.user` so the audit middleware can access it.
    """
    if DEV_MODE:
        user = TokenData(
            email="dev@local",
            roles=[ROLE_ADMIN, ROLE_ANALYST, ROLE_READ_ONLY],
            sub="dev",
        )
        request.state.user = user
        return user

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        jwks = await _get_jwks()
        claims = _decode_token(credentials.credentials, jwks)
    except Exception as exc:
        log.warning("auth_failure", reason=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = TokenData(
        email=claims.get("preferred_username") or claims.get("email") or claims.get("upn", ""),
        roles=claims.get("roles", []),
        sub=claims.get("sub", ""),
    )
    request.state.user = user
    return user


def require_roles(*roles: str) -> Callable:
    """Dependency factory: enforce that the caller has at least one of `roles`.

    Usage::

        @router.get("/admin-only")
        async def admin_route(user = Depends(require_roles("admin"))):
            ...
    """
    async def _check(user: TokenData = Depends(get_current_user)) -> TokenData:
        if not user.has_role(*roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {list(roles)}",
            )
        return user

    return _check
