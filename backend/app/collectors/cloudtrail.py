"""Normalize CloudTrail export files into observed access (principal, resource, action class).

A customer exports CloudTrail logs (the ``{"Records": [...]}`` JSON files CloudTrail
delivers to S3, optionally gzip-compressed, a JSON array of records, or one record
per line) and uploads them file by file. Each record is mapped with
``execution_audit.EVENTS`` and aggregated per (principal, resource, action class,
service) with first/last seen and a count. Nothing here decides that access is
unused: unmapped events are counted per service and make that service's coverage
incomplete, and events outside the declared window are ignored.

* **Principal**: the role ARN of an assumed-role session (``sessionIssuer.arn``),
  otherwise the IAM user/root ARN. Service principals and cross-account callers
  without an ARN are counted as unresolved.
* **Resource**: per service: the S3 bucket, the assumed role, the Glue table or
  database (names lowercased, as the Data Catalog stores them), the Athena workgroup, the Lake Formation table, the RDS Data API resource,
  else the first ``resources[].ARN``. Records without one are counted as unresolved.
* Records with an ``errorCode`` (for example ``AccessDenied``) are denied attempts:
  counted, never treated as use. Denied attempts whose principal and resource resolve
  are aggregated separately per (principal, resource, service, error code) with
  first/last seen and a count (bounded per file), for the optimizer rollout's
  AccessDenied watch after a least-privilege change is merged.

**Role sessions** (``userIdentity.type`` ``AssumedRole``) are also kept per session so
the upload's commit can attribute each access to the principal that assumed the role
(``app.graph.usage.attribute``):

* every successful ``AssumeRole``/``AssumeRoleWithWebIdentity``/``AssumeRoleWithSAML``
  in the window is an **issuance**: the new session's key
  (``responseElements.credentials.accessKeyId``) and ARN
  (``responseElements.assumedRoleUser.arn``), the role, the ``sourceIdentity`` set, and
  who assumed it: an IAM user or root ARN, ``service:<host>`` (AWS service),
  ``web-identity:<provider>:<user>``, ``saml:<provider>:<user>``, or, for role chaining,
  the parent session's key and its role;
* every successful mapped event made in a role session is aggregated per (role,
  session key, session ARN, ``sourceIdentity``, ``onBehalfOf``, resource, action
  class, service). Its role-level row in ``access`` is unchanged.
"""

import gzip
import io
import json
from dataclasses import dataclass, field
from datetime import datetime

from app.collectors.execution_audit import EVENTS, service_of

MAX_DECOMPRESSED_BYTES = 64 * 2**20
MAX_RECORDS = 500_000
MAX_ID = 512
MAX_DENIED_PAIRS = 20_000  # Distinct denied (principal, resource, service, code) per file.
MAX_ERROR_CODE = 64
MAX_KEY = 128  # Access key IDs (AWS: 16-128 characters) and session descriptors.
ISSUING = frozenset({"AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML"})


class ExportError(ValueError):
    """A client-correctable problem with an export file; never echoes record contents."""


def decode_export(body: bytes) -> list[dict]:
    """Records of one export file: gzip or plain JSON (``Records`` object, array or JSON lines)."""
    if body[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                body = stream.read(MAX_DECOMPRESSED_BYTES + 1)
        except (OSError, EOFError):
            raise ExportError("File is not valid gzip") from None
        if len(body) > MAX_DECOMPRESSED_BYTES:
            raise ExportError("Decompressed file exceeds the size limit")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ExportError("File must be UTF-8 JSON") from None
    try:
        value = json.loads(text)
    except ValueError:
        try:
            value = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError:
            raise ExportError("File is not CloudTrail JSON") from None
    if isinstance(value, dict):
        value = value.get("Records")
    if not isinstance(value, list) or not all(isinstance(record, dict) for record in value):
        raise ExportError("Expected a CloudTrail Records array")
    if len(value) > MAX_RECORDS:
        raise ExportError("File has too many records")
    return value


def _partition(arn: str) -> str:
    parts = arn.split(":")
    return parts[1] if len(parts) > 1 and parts[0] == "arn" and parts[1] else "aws"


def principal_of(record: dict) -> str:
    identity = record.get("userIdentity")
    if not isinstance(identity, dict):
        return ""
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    if identity.get("type") in ("AssumedRole", "FederatedUser") or issuer.get("arn"):
        arn = issuer.get("arn")
        if isinstance(arn, str) and arn:
            return arn
    arn = identity.get("arn")
    if isinstance(arn, str) and identity.get("type") in (None, "IAMUser", "Root"):
        return arn
    return ""


def _resources(record: dict, kind: str) -> str:
    for item in record.get("resources") or ():
        if isinstance(item, dict) and item.get("type") == kind and isinstance(item.get("ARN"), str):
            return item["ARN"]
    return ""


def resource_of(record: dict, service: str, principal: str) -> str:
    request = record.get("requestParameters")
    request = request if isinstance(request, dict) else {}
    partition = _partition(principal)
    region = record.get("awsRegion") or ""
    account = record.get("recipientAccountId") or ""
    if service == "s3":
        bucket = _resources(record, "AWS::S3::Bucket")
        if bucket:
            return bucket
        name = request.get("bucketName")
        return f"arn:{partition}:s3:::{name}" if isinstance(name, str) and name else ""
    if service == "sts":
        role = request.get("roleArn")
        return role if isinstance(role, str) and role else _resources(record, "AWS::IAM::Role")
    if service == "glue":
        if "Database" in str(record.get("eventName", "")):
            database, table = request.get("name") or request.get("databaseName"), None
        else:
            database = request.get("databaseName")
            table = request.get("tableName") or request.get("name")
            if not table and isinstance(request.get("tableInput"), dict):
                table = request["tableInput"].get("name")
        if isinstance(database, str) and database and region and account:
            # The Data Catalog stores database and table names in lowercase (the collector's
            # IDs use the stored names); a request may spell them in any case.
            if isinstance(table, str) and table:
                return f"arn:{partition}:glue:{region}:{account}:table/{database.lower()}/{table.lower()}"
            return f"arn:{partition}:glue:{region}:{account}:database/{database.lower()}"
    if service == "athena":
        group = request.get("workGroup") or "primary"
        if isinstance(group, str) and region and account:
            return f"arn:{partition}:athena:{region}:{account}:workgroup/{group}"
    if service == "lakeformation":
        table = request.get("tableArn")
        if isinstance(table, str) and table:
            return table
    if service == "rds-data":
        target = request.get("resourceArn")
        if isinstance(target, str) and target:
            return target
    for item in record.get("resources") or ():
        if isinstance(item, dict) and isinstance(item.get("ARN"), str) and item["ARN"]:
            return item["ARN"]
    return ""


def _text(value, limit: int = MAX_ID) -> str:
    return value if isinstance(value, str) and 0 < len(value) <= limit else ""


def issuer_of(identity: dict) -> tuple[str, str, str]:
    """(principal, parent session key, parent role) of the caller of an STS issuing call.

    The principal is set for a non-session caller (IAM user or root ARN, ``service:``,
    ``web-identity:`` or ``saml:`` principal); a role session (role chaining) gives its own
    session key and role instead. Unidentifiable callers give empty strings.
    """
    kind = identity.get("type")
    if kind == "AssumedRole":
        issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
        role = _text(issuer.get("arn")) if isinstance(issuer, dict) else ""
        return "", _text(identity.get("accessKeyId"), MAX_KEY), role
    if kind in ("IAMUser", "Root"):
        return _text(identity.get("arn")), "", ""
    if kind == "AWSService":
        host = _text(identity.get("invokedBy"), 256)
        return (f"service:{host}" if host else ""), "", ""
    if kind in ("WebIdentityUser", "SAMLUser"):
        provider = _text(identity.get("identityProvider"), 256)
        user = _text(identity.get("userName"), 256)
        if provider and user:
            prefix = "web-identity" if kind == "WebIdentityUser" else "saml"
            return _text(f"{prefix}:{provider}:{user}"), "", ""
    return "", "", ""


def on_behalf_of(identity: dict) -> str:
    """IAM Identity Center user a session acts for (``onBehalfOf``), as ``identity-center:...``."""
    found = identity.get("onBehalfOf")
    if not isinstance(found, dict):
        return ""
    user = _text(found.get("userId"), 256)
    store = _text(found.get("identityStoreArn"), 256)
    return _text(f"identity-center:{store}:{user}") if user else ""


def session_of(identity: dict) -> tuple[str, str, str, str] | None:
    """(key, session ARN, sourceIdentity, onBehalfOf) of a role-session caller, else None."""
    if identity.get("type") != "AssumedRole":
        return None
    context = identity.get("sessionContext")
    context = context if isinstance(context, dict) else {}
    source = _text(context.get("sourceIdentity"), MAX_KEY) or _text(identity.get("sourceIdentity"), MAX_KEY)
    return (
        _text(identity.get("accessKeyId"), MAX_KEY),
        _text(identity.get("arn")),
        source,
        on_behalf_of(identity),
    )


@dataclass
class Normalized:
    """Aggregated observed access of one export file, and how every record was classified."""

    # (principal, resource, action class, service) -> [first seen, last seen, count]
    access: dict[tuple[str, str, str, str], list] = field(default_factory=dict)
    records: int = 0
    matched: int = 0
    outside_window: int = 0
    denied: int = 0
    malformed: int = 0
    unresolved_principal: int = 0
    unresolved_resource: int = 0
    # service -> records seen / unmapped (no verified IAM action mapping)
    service_events: dict[str, int] = field(default_factory=dict)
    service_unmapped: dict[str, int] = field(default_factory=dict)
    # (principal, resource, service, error code) -> [first seen, last seen, count]; never use.
    denied_access: dict[tuple[str, str, str, str], list] = field(default_factory=dict)
    denied_unrecorded: int = 0
    # Session key -> [session ARN, role, principal, parent key, parent role, sourceIdentity, issued at].
    issued: dict[str, list] = field(default_factory=dict)
    # (role, key, session ARN, sourceIdentity, onBehalfOf, resource, action class, service)
    # -> [first seen, last seen, count]: the role-session part of ``access``.
    sessions: dict[tuple[str, str, str, str, str, str, str, str], list] = field(default_factory=dict)
    issued_unkeyed: int = 0

    def stats(self) -> dict:
        return {
            "records": self.records,
            "matched": self.matched,
            "outside_window": self.outside_window,
            "denied": self.denied,
            "malformed": self.malformed,
            "unresolved_principal": self.unresolved_principal,
            "unresolved_resource": self.unresolved_resource,
            "unmapped": sum(self.service_unmapped.values()),
            "service_events": dict(sorted(self.service_events.items())),
            "service_unmapped": dict(sorted(self.service_unmapped.items())),
            "pairs": len(self.access),
            "denied_pairs": len(self.denied_access),
            "denied_unrecorded": self.denied_unrecorded,
            "sessions_issued": len(self.issued),
            "issued_unkeyed": self.issued_unkeyed,
            "session_events": sum(row[2] for row in self.sessions.values()),
        }


def _time(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _record_denial(result: Normalized, record: dict, service: str, occurred: datetime) -> None:
    """Aggregate a denied attempt by (principal, resource, service, error code); never use."""
    code = record.get("errorCode")
    principal = principal_of(record)
    resource = resource_of(record, service, principal) if principal else ""
    if (
        not isinstance(code, str)
        or not principal
        or not resource
        or len(principal) > MAX_ID
        or len(resource) > MAX_ID
    ):
        result.denied_unrecorded += 1
        return
    key = (principal, resource, service, code[:MAX_ERROR_CODE])
    row = result.denied_access.get(key)
    if row is None:
        if len(result.denied_access) >= MAX_DENIED_PAIRS:
            result.denied_unrecorded += 1
            return
        result.denied_access[key] = [occurred, occurred, 1]
        return
    row[0], row[1], row[2] = min(row[0], occurred), max(row[1], occurred), row[2] + 1


def _record_issuance(result: Normalized, record: dict, occurred: datetime) -> None:
    """Remember who assumed which role session (key, ARN) from a successful STS call."""
    response = record.get("responseElements")
    response = response if isinstance(response, dict) else {}
    credentials = response.get("credentials")
    key = _text(credentials.get("accessKeyId"), MAX_KEY) if isinstance(credentials, dict) else ""
    assumed = response.get("assumedRoleUser")
    arn = _text(assumed.get("arn")) if isinstance(assumed, dict) else ""
    request = record.get("requestParameters")
    request = request if isinstance(request, dict) else {}
    role = _text(request.get("roleArn"))
    identity = record.get("userIdentity")
    principal, parent, parent_role = issuer_of(identity) if isinstance(identity, dict) else ("", "", "")
    if not key or not role or not (principal or parent):
        result.issued_unkeyed += 1
        return
    source = _text(request.get("sourceIdentity"), MAX_KEY)
    found = result.issued.get(key)
    if found is None or occurred < found[6]:
        result.issued[key] = [arn, role, principal, parent, parent_role, source, occurred]


def _record_session(result: Normalized, identity: dict, key: tuple, occurred: datetime) -> None:
    session = session_of(identity)
    if session is None:
        return
    principal, resource, action_class, service = key
    full = (principal, *session, resource, action_class, service)
    row = result.sessions.get(full)
    if row is None:
        result.sessions[full] = [occurred, occurred, 1]
    else:
        row[0], row[1], row[2] = min(row[0], occurred), max(row[1], occurred), row[2] + 1


def normalize_export(records: list[dict], start: datetime, end: datetime) -> Normalized:
    """Aggregate one file's records observed inside ``[start, end]`` (timezone-aware)."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("Usage window requires timezone-aware timestamps")
    result = Normalized()
    access = result.access
    for record in records:
        result.records += 1
        source = record.get("eventSource")
        occurred = _time(record.get("eventTime"))
        if not isinstance(source, str) or occurred is None:
            result.malformed += 1
            continue
        if not start <= occurred <= end:
            result.outside_window += 1
            continue
        service = service_of(source)
        result.service_events[service] = result.service_events.get(service, 0) + 1
        mapped = EVENTS.get((source, record.get("eventName")))
        if mapped is None:
            result.service_unmapped[service] = result.service_unmapped.get(service, 0) + 1
            continue
        if record.get("errorCode"):
            result.denied += 1
            _record_denial(result, record, service, occurred)
            continue
        if service == "sts" and record.get("eventName") in ISSUING:
            _record_issuance(result, record, occurred)
        principal = principal_of(record)
        if not principal or len(principal) > MAX_ID:
            result.unresolved_principal += 1
            continue
        resource = resource_of(record, service, principal)
        if not resource or len(resource) > MAX_ID:
            result.unresolved_resource += 1
            continue
        result.matched += 1
        key = (principal, resource, mapped[1], service)
        row = access.get(key)
        if row is None:
            access[key] = [occurred, occurred, 1]
        else:
            if occurred < row[0]:
                row[0] = occurred
            if occurred > row[1]:
                row[1] = occurred
            row[2] += 1
        identity = record["userIdentity"]
        if identity.get("type") == "AssumedRole":
            _record_session(result, identity, key, occurred)
    return result
