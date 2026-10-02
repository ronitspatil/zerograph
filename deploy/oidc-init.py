"""Generate ephemeral OIDC drill credentials/CA outside the repository; never overwrite."""

import argparse
import ipaddress
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write(path: Path, content: str | bytes, mode: int = 0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    args = parser.parse_args()
    if (
        args.directory.is_symlink()
        or args.env_file.exists()
        or args.env_file.is_symlink()
    ):
        parser.error("Fixture must not use symlinks or an existing environment file")
    directory = args.directory.resolve()
    if directory.parent != Path("/tmp").resolve() or not directory.name.startswith(
        "zerograph-oidc-qualification."
    ):
        parser.error("Use a dedicated /tmp/zerograph-oidc-qualification.* directory")
    if directory.exists() and list(directory.iterdir()):
        parser.error("Fixture directory must be absent or empty")
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        parser.error("Fixture directory must be private and owned by the current user")
    nonce = secrets.token_hex(32)
    write(
        directory / ".owner.json",
        json.dumps(
            {
                "kind": "zerograph-oidc-qualification",
                "directory": str(directory),
                "env_file": str(args.env_file.resolve()),
                "uid": os.getuid(),
                "nonce": nonce,
            }
        ),
    )
    (directory / "certs").mkdir(mode=0o755)
    (directory / "realm").mkdir(mode=0o755)
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Disposable ZeroGraph OIDC CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = ["auth.oidc.test", "console.oidc.test", "api.oidc.test"]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    *(x509.DNSName(name) for name in names),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    write(
        directory / "certs/ca.crt", ca.public_bytes(serialization.Encoding.PEM), 0o644
    )
    write(
        directory / "certs/server.crt",
        cert.public_bytes(serialization.Encoding.PEM),
        0o644,
    )
    write(
        directory / "certs/server.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )

    accounts = {}
    users = []
    for username, tenant, role in [
        ("admin-a", "tenant-a", "admin"),
        ("analyst-a", "tenant-a", "analyst"),
        ("viewer-a", "tenant-a", "viewer"),
        ("admin-b", "tenant-b", "admin"),
        ("no-role", "tenant-a", None),
        ("no-tenant", None, "viewer"),
    ]:
        password = secrets.token_urlsafe(24)
        accounts[username] = password
        users.append(
            {
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "firstName": "Disposable",
                "lastName": "Fixture",
                "email": username + "@oidc.test",
                "requiredActions": [],
                "attributes": {"tenant_id": [tenant]} if tenant else {},
                "realmRoles": [role] if role else [],
                "credentials": [
                    {"type": "password", "value": password, "temporary": False}
                ],
            }
        )
    mappers = [
        {
            "name": "tenant",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": "tenant_id",
                "claim.name": "tenant_id",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "multivalued": "false",
            },
        },
        {
            "name": "roles",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "claim.name": "roles",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "multivalued": "true",
            },
        },
    ]
    clients = []
    for client_id, audience, ttl in [
        ("zerograph-web", "zerograph-api", 60),
        ("short-lived", "zerograph-api", 5),
        ("wrong-audience", "other-api", 60),
    ]:
        clients.append(
            {
                "clientId": client_id,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": True,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "implicitFlowEnabled": False,
                "redirectUris": ["https://console.oidc.test:8443/api/auth/callback"],
                "webOrigins": ["https://console.oidc.test:8443"],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "access.token.lifespan": str(ttl),
                },
                "protocolMappers": [
                    *mappers,
                    {
                        "name": "audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.custom.audience": audience,
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                ],
            }
        )
    realm = {
        "realm": "zerograph",
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False,
        "accessTokenLifespan": 60,
        "ssoSessionIdleTimeout": 300,
        "ssoSessionMaxLifespan": 600,
        "roles": {"realm": [{"name": role} for role in ["viewer", "analyst", "admin"]]},
        "clients": clients,
        "users": users,
    }
    write(directory / "realm/zerograph-realm.json", json.dumps(realm), 0o644)
    write(directory / "accounts.json", json.dumps(accounts))
    root = Path(__file__).resolve().parents[1]
    config = (
        (root / ".env.example")
        .read_text()
        .replace("replace-with-random-64-character-token", secrets.token_hex(32))
        .replace("replace-with-random-64-character-secret", secrets.token_hex(32))
        .replace("replace-with-random-password", secrets.token_hex(24))
    )
    config += f"\nZG_OIDC_FIXTURE_DIR={directory}\nZG_OIDC_FIXTURE_OWNER={nonce}\nOIDC_DB_PASSWORD={secrets.token_hex(24)}\n"
    write(args.env_file, config)
    print(
        "Generated disposable OIDC fixture configuration and CA; no credentials are printed."
    )


if __name__ == "__main__":
    main()
