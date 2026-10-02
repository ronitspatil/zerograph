import time
from types import SimpleNamespace
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError

from app.core.auth import current_actor
from app.core.config import Settings, get_settings


@pytest.fixture
def oidc(monkeypatch):
    monkeypatch.setenv("ZG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("ZG_OIDC_JWKS_URL", "https://issuer.example/keys")
    get_settings.cache_clear()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with patch("app.core.auth.jwks_client") as client:
        client.return_value.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
        yield key
    get_settings.cache_clear()


def token(key, **changes):
    claims = {
        "iss": "https://issuer.example",
        "aud": "zerograph-api",
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "sub": "alice",
        "tenant_id": "tenant-a",
        "roles": ["analyst"],
    }
    claims.update(changes)
    return HTTPAuthorizationCredentials(
        scheme="Bearer", credentials=jwt.encode(claims, key, algorithm="RS256")
    )


def test_verified_oidc_token_binds_tenant_and_roles(oidc):
    actor = current_actor(token(oidc))
    assert actor.tenant_id == "tenant-a"
    assert actor.roles == frozenset({"analyst"})


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong"},
        {"iss": "https://attacker.example"},
        {"exp": 1},
        {"tenant_id": None},
        {"roles": "admin"},
        {"tenant_id": ""},
    ],
)
def test_invalid_claims_rejected(oidc, changes):
    with pytest.raises(HTTPException) as exc:
        current_actor(token(oidc, **changes))
    assert exc.value.status_code == 401


def test_demo_token_and_unknown_token():
    actor = current_actor(HTTPAuthorizationCredentials(scheme="Bearer", credentials="a" * 64))
    assert actor.tenant_id == "demo"
    with pytest.raises(HTTPException):
        current_actor(HTTPAuthorizationCredentials(scheme="Bearer", credentials="unknown"))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"environment": "production", "demo_mode": True},
        {"environment": "production", "demo_mode": False, "graph_vendor": "memory"},
        {"environment": "production", "demo_mode": False, "graph_vendor": "memgraph"},
        {"environment": "development", "demo_mode": True, "demo_token": "short"},
    ],
)
def test_insecure_configuration_is_rejected(kwargs):
    with pytest.raises(ValidationError):
        Settings(**kwargs)
