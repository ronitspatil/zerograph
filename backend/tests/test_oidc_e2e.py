"""Real disposable Keycloak + HTTPS production-mode qualification via HTTP forms.

No browser automation claims. Failure messages contain only fixed step labels;
provider URLs with authorization codes, cookies and tokens are never printed.
"""

import base64
import hashlib
import json
import os
import secrets
import ssl
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import jwt
import pytest

CONSOLE = "https://console.oidc.test:8443"
AUTH = "https://auth.oidc.test:8443"
API = "https://api.oidc.test:8443"
ISSUER = AUTH + "/realms/zerograph"
CALLBACK = CONSOLE + "/api/auth/callback"
pytestmark = pytest.mark.skipif(
    os.getenv("ZG_OIDC_E2E") != "true", reason="Disposable HTTPS OIDC stack is not configured"
)


class QualificationError(Exception):
    pass


def check(condition, label):
    if not condition:
        raise QualificationError(label)


@contextmanager
def sanitized_case():
    try:
        yield
    except QualificationError as exc:
        pytest.fail(str(exc), pytrace=False)
    except Exception as exc:
        pytest.fail(f"OIDC drill infrastructure failure ({type(exc).__name__})", pytrace=False)


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = {}
        self.inside = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs.get("action")
            self.inside = True
        if self.inside and tag == "input" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False


class Drill:
    def __init__(self):
        directory = Path(os.environ["ZG_OIDC_FIXTURE_DIR"])
        self.context = ssl.create_default_context(cafile=str(directory / "certs/ca.crt"))
        self.accounts = json.loads((directory / "accounts.json").read_text())
        with self.client() as client:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    response = client.get(ISSUER + "/.well-known/openid-configuration")
                    if response.status_code == 200 and response.json().get("issuer") == ISSUER:
                        break
                except (httpx.TransportError, ValueError):
                    pass
                time.sleep(1)
            else:
                raise QualificationError(
                    "Disposable provider did not publish HTTPS discovery within 120 seconds"
                )

    def client(self):
        return httpx.Client(verify=self.context, trust_env=False, timeout=15, follow_redirects=False)

    def provider_login(self, client, authorization_url, username):
        parsed = urlparse(authorization_url)
        check(
            parsed.scheme == "https" and f"https://{parsed.netloc}" == AUTH,
            "Authorization redirect must stay on the trusted HTTPS provider",
        )
        response = client.get(authorization_url)
        check(response.status_code == 200, "Provider login form must load")
        form = LoginForm()
        form.feed(response.text)
        check(form.action is not None, "Expected provider login form is required")
        action = urljoin(AUTH, form.action)
        check(action.startswith(AUTH + "/"), "Provider form action must remain same-origin HTTPS")
        response = client.post(
            action,
            data={**form.fields, "username": username, "password": self.accounts[username]},
            headers={"Origin": AUTH},
        )
        for _ in range(8):
            check(
                response.status_code in {302, 303, 307},
                "Provider must authorize the disposable fixture account",
            )
            location = urljoin(str(response.url), response.headers.get("location", ""))
            if location.startswith(CALLBACK + "?"):
                check(
                    "code" in parse_qs(urlparse(location).query), "Provider must return an authorization code"
                )
                return location
            check(location.startswith(AUTH + "/"), "Unexpected provider redirect destination")
            response = client.get(location)
        raise QualificationError("Provider redirect limit exceeded")

    def login(self, client, username, permitted=True):
        response = client.get(CONSOLE + "/api/auth/login")
        check(response.status_code == 307, "Frontend must redirect to real OIDC authorization")
        authorization_url = response.headers.get("location", "")
        query = parse_qs(urlparse(authorization_url).query)
        check(query.get("code_challenge_method") == ["S256"], "Frontend must request S256 PKCE")
        check(
            len(query.get("code_challenge", [""])[0]) == 43,
            "Frontend PKCE challenge must be SHA-256 base64url",
        )
        callback = self.provider_login(client, authorization_url, username)
        response = client.get(callback)
        check(response.status_code == 307, "OAuth callback must redirect without disclosing tokens")
        if permitted:
            check(
                response.headers.get("location") == CONSOLE + "/",
                "Provider token must pass backend signed role/tenant verification",
            )
            cookies = SimpleCookie()
            for header in response.headers.get_list("set-cookie"):
                cookies.load(header)
            check("zg_session" in cookies, "Verified login must issue encrypted session cookie")
            cookie = cookies["zg_session"]
            check(
                bool(cookie["secure"]) and bool(cookie["httponly"]) and cookie["samesite"].lower() == "lax",
                "Production session must be Secure, HttpOnly and SameSite=Lax",
            )
            check(
                "access_token" not in cookie.value and len(cookie.value.split(".")) == 5,
                "Session cookie must be encrypted JWE",
            )
            return response, callback, cookie.value, int(cookie["max-age"])
        check(
            response.headers.get("location") == CONSOLE + "/login?error=authentication",
            "Unauthorized signed identity must not obtain a console session",
        )
        check(
            client.get(CONSOLE + "/api/zg/me").status_code == 401,
            "Denied identity must remain unauthenticated in BFF",
        )
        return response, callback, None, 0

    def code(self, client, username, client_id="short-lived"):
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        authorization = str(
            httpx.URL(
                ISSUER + "/protocol/openid-connect/auth",
                params={
                    "client_id": client_id,
                    "response_type": "code",
                    "scope": "openid",
                    "redirect_uri": CALLBACK,
                    "state": secrets.token_urlsafe(16),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
            )
        )
        callback = self.provider_login(client, authorization, username)
        return parse_qs(urlparse(callback).query)["code"][0], verifier

    def exchange(self, client, code, verifier, client_id="short-lived"):
        return client.post(
            ISSUER + "/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": CALLBACK,
                "code": code,
                "code_verifier": verifier,
            },
        )

    def api(self, client, method, path, **kwargs):
        return client.request(method, CONSOLE + "/api/zg/" + path, headers={"Origin": CONSOLE}, **kwargs)


@pytest.fixture(scope="module")
def drill():
    with sanitized_case():
        return Drill()


def snapshot():
    return {
        "nodes": [
            {
                "id": "agent:fixture",
                "name": "Disposable Agent",
                "type": "AIAgent",
                "internet_exposed": True,
                "authenticated": False,
            },
            {
                "id": "data:fixture",
                "name": "Disposable Data",
                "type": "S3Bucket",
                "sensitivity": "restricted",
            },
        ],
        "edges": [
            {
                "source": "agent:fixture",
                "target": "data:fixture",
                "type": "CAN_READ",
                "certainty": "confirmed",
            }
        ],
    }


def preview():
    now = datetime.now(UTC)
    return {
        "identity_id": "agent:fixture",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"], "Resource": "*"}]
        },
        "usage": {
            "window_start": (now - timedelta(days=100)).isoformat(),
            "window_end": (now - timedelta(days=1)).isoformat(),
            "used_actions": ["s3:GetObject"],
            "covered_services": ["s3"],
            "complete": True,
            "source": "disposable-oidc-qualification",
        },
    }


def test_real_provider_roles_tenants_and_session_controls(drill):
    with sanitized_case(), drill.client() as admin:
        check(
            admin.post(CONSOLE + "/api/auth/demo", headers={"Origin": CONSOLE}).status_code == 403,
            "Demo login must be disabled in production",
        )
        drill.login(admin, "admin-a")
        actor = drill.api(admin, "GET", "me")
        check(
            actor.status_code == 200
            and actor.json()["tenant_id"] == "tenant-a"
            and "admin" in actor.json()["roles"],
            "Real admin claims must bind tenant and role",
        )
        ingestion = drill.api(admin, "POST", "ingestions", json={"source": "snapshot", "payload": snapshot()})
        check(ingestion.status_code == 202, "Real admin may create an ingestion")
        jid = ingestion.json()["id"]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            job = drill.api(admin, "GET", "ingestions/" + jid)
            check(job.status_code == 200, "Admin may poll own tenant job")
            check(job.json()["status"] != "failed", "Disposable ingestion must not fail")
            if job.json()["status"] == "completed":
                break
            time.sleep(0.5)
        else:
            raise QualificationError("Disposable ingestion did not complete within 30 seconds")
        check(
            drill.api(admin, "POST", "simulate", json={"node_id": "agent:fixture"}).status_code == 200,
            "Admin may simulate",
        )
        remediation = drill.api(admin, "POST", "remediations/preview", json=preview())
        check(remediation.status_code == 200, "Admin may preview least-privilege remediation")
        rid = remediation.json()["id"]
        check(drill.api(admin, "GET", "audit").status_code == 200, "Admin may read audit")
        for username, role in [("viewer-a", "viewer"), ("analyst-a", "analyst")]:
            with drill.client() as user:
                drill.login(user, username)
                actor = drill.api(user, "GET", "me")
                check(
                    actor.status_code == 200 and role in actor.json()["roles"],
                    "Expected real provider application role",
                )
                check(
                    drill.api(user, "GET", "graph").status_code == 200,
                    "Viewer and analyst may read tenant graph",
                )
                expected = 403 if role == "viewer" else 200
                check(
                    drill.api(user, "POST", "simulate", json={"node_id": "agent:fixture"}).status_code
                    == expected,
                    "Simulation role boundary must be enforced",
                )
                check(
                    drill.api(user, "POST", "remediations/preview", json=preview()).status_code == expected,
                    "Remediation preview role boundary must be enforced",
                )
                check(
                    drill.api(
                        user, "POST", "ingestions", json={"source": "snapshot", "payload": snapshot()}
                    ).status_code
                    == 403,
                    "Viewer and analyst cannot ingest",
                )
                check(
                    drill.api(user, "GET", "audit").status_code == 403,
                    "Viewer and analyst cannot read admin audit",
                )
                check(
                    drill.api(user, "POST", f"remediations/{rid}/pr").status_code == 403,
                    "Viewer and analyst cannot create PRs",
                )
        with drill.client() as other:
            drill.login(other, "admin-b")
            check(
                drill.api(other, "GET", "me").json()["tenant_id"] == "tenant-b",
                "Second tenant uses its own signed claim",
            )
            check(
                drill.api(other, "GET", "graph").json()["nodes"] == [],
                "Second tenant must not see first tenant graph",
            )
            check(
                drill.api(other, "GET", "ingestions/" + jid).status_code == 404,
                "Cross-tenant existing job must not be found",
            )
            check(
                drill.api(other, "GET", f"remediations/{rid}/terraform").status_code == 404,
                "Cross-tenant remediation export must not be found",
            )
            check(
                drill.api(other, "POST", f"remediations/{rid}/pr").status_code == 404,
                "Cross-tenant PR request must not be found",
            )
            check(
                drill.api(other, "POST", "simulate", json={"node_id": "agent:fixture"}).status_code == 404,
                "Cross-tenant simulation must not expose assets",
            )
            for collection in ["ingestions", "remediations", "audit"]:
                check(
                    drill.api(other, "GET", collection).json() == [],
                    "Cross-tenant collection must remain empty",
                )
        for username in ["no-role", "no-tenant"]:
            with drill.client() as denied:
                drill.login(denied, username, permitted=False)
        check(
            admin.post(
                CONSOLE + "/api/auth/logout", headers={"Origin": "https://attacker.example"}
            ).status_code
            == 403,
            "Cross-origin logout must be denied",
        )
        check(drill.api(admin, "GET", "me").status_code == 200, "Denied logout must preserve session")
        with drill.client() as logout:
            drill.login(logout, "viewer-a")
            check(
                logout.post(
                    CONSOLE + "/api/auth/logout", headers={"Origin": "https://attacker.example"}
                ).status_code
                == 403,
                "Cross-origin logout must be denied",
            )
            check(drill.api(logout, "GET", "me").status_code == 200, "Denied logout must preserve session")
            check(
                logout.post(CONSOLE + "/api/auth/logout", headers={"Origin": CONSOLE}).status_code == 200,
                "Same-origin logout must clear app session",
            )
            check(
                drill.api(logout, "GET", "me").status_code == 401,
                "Logged-out session must no longer authenticate",
            )


def test_actual_pkce_signature_audience_and_replay_denial(drill):
    with sanitized_case():
        with drill.client() as bad:
            code, _ = drill.code(bad, "viewer-a")
            rejected = drill.exchange(bad, code, "w" * 43)
            check(
                rejected.status_code == 400 and rejected.json().get("error") == "invalid_grant",
                "Real provider must reject the PKCE challenge for a valid-format wrong verifier",
            )
        with drill.client() as valid:
            code, verifier = drill.code(valid, "viewer-a")
            token_response = drill.exchange(valid, code, verifier)
            check(token_response.status_code == 200, "Real provider must exchange correct PKCE code")
            token = token_response.json()["access_token"]
            check(
                valid.get(API + "/api/v1/me", headers={"Authorization": "Bearer " + token}).status_code
                == 200,
                "Backend must verify actual signed provider token",
            )
            check(
                drill.exchange(valid, code, verifier).status_code == 400,
                "Provider must deny authorization-code replay",
            )
            parts = token.split(".")
            parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
            check(
                valid.get(
                    API + "/api/v1/me", headers={"Authorization": "Bearer " + ".".join(parts)}
                ).status_code
                == 401,
                "Backend must reject modified signature",
            )
        with drill.client() as wrong_audience:
            code, verifier = drill.code(wrong_audience, "viewer-a", "wrong-audience")
            response = drill.exchange(wrong_audience, code, verifier, "wrong-audience")
            check(
                response.status_code == 200, "Provider must issue independently signed wrong-audience fixture"
            )
            check(
                wrong_audience.get(
                    API + "/api/v1/me", headers={"Authorization": "Bearer " + response.json()["access_token"]}
                ).status_code
                == 401,
                "Backend must reject provider-signed wrong audience",
            )
        with drill.client() as replay:
            _, callback, _, _ = drill.login(replay, "viewer-a")
            response = replay.get(callback)
            check(
                response.headers.get("location") == CONSOLE + "/login?error=authentication",
                "Frontend must deny callback replay after state cookie consumption",
            )
        with drill.client() as state:
            response = state.get(CONSOLE + "/api/auth/login")
            callback = drill.provider_login(state, response.headers["location"], "viewer-a")
            query = parse_qs(urlparse(callback).query)
            response = state.get(CALLBACK, params={"state": "wrong-state", "code": query["code"][0]})
            check(
                response.headers.get("location") == CONSOLE + "/login?error=authentication",
                "Frontend must deny mismatched OAuth state",
            )
            check(
                state.get(CONSOLE + "/api/zg/me").status_code == 401,
                "State mismatch must not create a session",
            )


def test_real_token_and_replayed_session_expire_with_bounded_clock_skew(drill):
    with sanitized_case(), drill.client() as client, drill.client() as direct:
        _, _, cookie, max_age = drill.login(client, "viewer-a")
        check(1 <= max_age <= 60, "Fixture frontend session lifetime must remain bounded")
        code, verifier = drill.code(direct, "viewer-a")
        response = drill.exchange(direct, code, verifier)
        check(response.status_code == 200, "Short-lived provider token must be issued")
        token = response.json()["access_token"]
        claims = jwt.decode(
            token, options={"verify_signature": False}
        )  # Timing only; backend performs actual verification.
        check(claims["exp"] - claims["iat"] <= 5, "Fixture access-token TTL must be five seconds")
        check(
            direct.get(API + "/api/v1/me", headers={"Authorization": "Bearer " + token}).status_code == 200,
            "Short-lived token initially authenticates",
        )
        deadline = max(time.time() + max_age + 11, claims["exp"] + 31)
        check(
            deadline - time.time() <= 75, "Expiry wait must be bounded including backend/JWE clock tolerance"
        )
        while time.time() < deadline:
            time.sleep(min(1, deadline - time.time()))
        check(
            direct.get(API + "/api/v1/me", headers={"Authorization": "Bearer " + token}).status_code == 401,
            "Actual provider token must expire beyond backend leeway",
        )
        check(
            client.get(CONSOLE + "/api/zg/me", headers={"Cookie": "zg_session=" + cookie}).status_code == 401,
            "Replayed expired encrypted session must fail server-side",
        )
