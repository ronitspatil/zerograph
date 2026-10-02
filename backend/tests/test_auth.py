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
        {"roles": ["admin"] * 65},
        {"roles": ["a" * 129]},
        {"iat": int(time.time()) + 3600},
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


@pytest.mark.parametrize("value", ["non-ascii-\u2603", "a" * 16385])
def test_malformed_bearer_is_rejected_without_key_lookup(value):
    with patch("app.core.auth.jwks_client") as client:
        with pytest.raises(HTTPException) as exc:
            current_actor(HTTPAuthorizationCredentials(scheme="Bearer", credentials=value))
        assert exc.value.status_code == 401
        client.assert_not_called()


@pytest.mark.parametrize("sub", ["", "   ", "a" * 257])
def test_invalid_subject_rejected(oidc, sub):
    with pytest.raises(HTTPException) as exc:
        current_actor(token(oidc, sub=sub))
    assert exc.value.status_code == 401


def test_jwks_rotation_drops_removed_keys(monkeypatch):
    """Exercise real PyJWKClient selection with a rotating local JWKS fixture."""
    import json

    from app.core.auth import jwks_client

    monkeypatch.setenv("ZG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("ZG_OIDC_JWKS_URL", "https://issuer.example/keys")
    get_settings.cache_clear()
    jwks_client.cache_clear()
    old = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = []
    for kid, key in [("old", old), ("new", new)]:
        keys.append({**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())), "kid": kid})
    client = jwks_client("https://issuer.example/keys")

    def fetch():
        payload = {"keys": keys.copy()}
        client.jwk_set_cache.put(payload)
        return payload

    monkeypatch.setattr(client, "fetch_data", fetch)

    def credentials(key, kid):
        claims = jwt.decode(token(key).credentials, options={"verify_signature": False})
        return HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})
        )

    try:
        assert current_actor(credentials(old, "old")).tenant_id == "tenant-a"
        keys.pop(0)
        client.jwk_set_cache.put(None)  # Simulate the bounded JWKS cache expiring.
        assert current_actor(credentials(new, "new")).tenant_id == "tenant-a"
        with pytest.raises(HTTPException) as exc:
            current_actor(credentials(old, "old"))
        assert exc.value.status_code == 401
    finally:
        jwks_client.cache_clear()
        get_settings.cache_clear()


@pytest.mark.parametrize("roles, permitted", [([], False), (["unrelated"], False), (["viewer"], True), (["analyst"], True), (["admin"], True)])
def test_read_endpoints_require_application_role(environment, roles, permitted):
    from fastapi.testclient import TestClient

    from app.core.auth import Actor
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("alice", "tenant-a", frozenset(roles))
    with TestClient(app) as client:
        for endpoint in ["me", "graph", "overview", "findings"]:
            assert client.get(f"/api/v1/{endpoint}").status_code == (200 if permitted else 403)


def test_wrong_signature_is_rejected(oidc):
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException) as exc:
        current_actor(token(attacker))
    assert exc.value.status_code == 401
