import hmac
from dataclasses import dataclass
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from app.core.config import get_settings
from app.core.rate_limit import enforce_rate_limit

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Actor:
    subject: str
    tenant_id: str
    roles: frozenset[str]


@lru_cache
def jwks_client(url: str) -> PyJWKClient:
    return PyJWKClient(url, cache_keys=False, lifespan=300, timeout=5)


def current_actor(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Actor:
    if credentials is None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    settings = get_settings()
    token = credentials.credentials
    if len(token) > 16_384 or not token.isascii():
        raise HTTPException(401, "Invalid access token", headers={"WWW-Authenticate": "Bearer"})
    if settings.demo_mode and hmac.compare_digest(token, settings.demo_token.get_secret_value()):
        enforce_rate_limit("demo", "demo-user")
        return Actor("demo-user", "demo", frozenset({"viewer", "analyst", "admin"}))
    if not settings.oidc_jwks_url:
        raise HTTPException(401, "OIDC authentication is not configured")
    try:
        key = jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "sub"]},
            leeway=30,
        )
        tenant = claims.get(settings.tenant_claim)
        roles = claims.get(settings.role_claim, [])
        if not isinstance(tenant, str) or not tenant or len(tenant) > 128:
            raise ValueError("Invalid tenant claim")
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject.strip() or len(subject) > 256:
            raise ValueError("Invalid subject claim")
        if not isinstance(roles, list) or len(roles) > 64 or not all(
            isinstance(r, str) and len(r) <= 128 for r in roles
        ):
            raise ValueError("Invalid role claim")
        enforce_rate_limit(tenant, claims["sub"])
        return Actor(claims["sub"], tenant, frozenset(roles))
    except (jwt.PyJWTError, jwt.PyJWKClientError, ValueError) as exc:
        raise HTTPException(401, "Invalid access token", headers={"WWW-Authenticate": "Bearer"}) from exc


def require_role(role: str):
    def authorize(actor: Actor = Depends(current_actor)) -> Actor:
        allowed = {role, "admin"}
        if role == "viewer":
            allowed.add("analyst")
        if not actor.roles.intersection(allowed):
            raise HTTPException(403, f"{role} role required")
        return actor

    return authorize
