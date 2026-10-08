from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ZG_", env_file=".env", extra="ignore", hide_input_in_errors=True
    )
    environment: Literal["development", "test", "production"] = "development"
    demo_mode: bool = False
    demo_token: SecretStr = SecretStr("")
    database_url: str = "postgresql+psycopg://zerograph:zerograph@postgres:5432/zerograph"
    redis_url: str = "redis://redis:6379/0"
    graph_uri: str = "bolt://memgraph:7687"
    graph_vendor: Literal["memgraph", "neo4j", "memory"] = "memgraph"
    graph_username: str = ""
    graph_password: SecretStr = SecretStr("")
    oidc_issuer: str = ""
    oidc_audience: str = "zerograph-api"
    oidc_jwks_url: str = ""
    tenant_claim: str = "tenant_id"
    role_claim: str = "roles"
    query_timeout_seconds: int = Field(default=15, ge=1, le=120)
    metrics_token: SecretStr = SecretStr("")
    body_timeout_seconds: int = Field(default=30, ge=1, le=120)
    max_body_bytes: int = Field(default=4_000_000, ge=1024)
    # Per-revision publication caps (the captain's capacity target), enforced on upload
    # sessions, inline snapshots and the merged revision at publication time.
    max_nodes: int = Field(default=100_000, ge=1, le=1_000_000)
    max_edges: int = Field(default=500_000, ge=1, le=5_000_000)
    # Deprecated whole-revision GET /graph: larger revisions get 413 instead of a full
    # serialization (the pre-scale snapshot caps; use /graph/explore and /graph/clusters).
    legacy_graph_max_nodes: int = Field(default=5_000, ge=1, le=1_000_000)
    legacy_graph_max_edges: int = Field(default=20_000, ge=1, le=5_000_000)
    # Rows per graph write/delete transaction during publication and retention.
    graph_batch_size: int = Field(default=5000, ge=100, le=50_000)
    upload_session_ttl_seconds: int = Field(default=86_400, ge=300, le=7 * 86_400)
    max_open_uploads: int = Field(default=4, ge=1, le=100)
    aws_tenant_id: str = ""
    aws_role_arn: str = ""
    aws_external_id: SecretStr = SecretStr("")
    aws_region: str = "us-east-1"
    # Optional IAM Access Advisor last-accessed hints (needs the Access Advisor permissions).
    aws_access_advisor: bool = False
    # Peer baseline for inferred need: a grant is needed when at least this share of
    # same-topic, same-role peers were observed using it.
    peer_baseline_share: float = Field(default=0.5, gt=0, le=1)
    git_provider: Literal["github", "gitlab"] = "github"
    git_repository: str = ""
    git_tenant_id: str = ""
    git_base_branch: str = "main"
    git_token: SecretStr = SecretStr("")
    git_policy_prefix: str = "security/zerograph"
    # Optimizer rollout: canary watch window after a change is marked merged, and the
    # AccessDenied events (per change, inside the window) that flag it for revert.
    rollout_watch_days: int = Field(default=7, ge=1, le=90)
    rollout_denied_threshold: int = Field(default=1, ge=1, le=1_000_000)

    @model_validator(mode="after")
    def secure_configuration(self) -> "Settings":
        if self.demo_mode and len(self.demo_token.get_secret_value()) < 32:
            raise ValueError("Demo mode requires a random token of at least 32 characters")
        metrics = self.metrics_token.get_secret_value()
        if metrics and (
            len(metrics) < 32
            or len(metrics) > 4096
            or not metrics.isascii()
            or not metrics.isprintable()
            or any(character.isspace() for character in metrics)
        ):
            raise ValueError(
                "Metrics scraping requires a printable ASCII secret of 32 to 4096 characters without whitespace"
            )
        if metrics and metrics in {self.demo_token.get_secret_value(), self.git_token.get_secret_value()}:
            raise ValueError("Metrics scraping must use a separate secret")
        if self.environment == "production":
            if self.demo_mode or self.graph_vendor == "memory":
                raise ValueError("Demo authentication and memory graphs are prohibited in production")
            if not self.oidc_issuer.startswith("https://") or not self.oidc_jwks_url.startswith("https://"):
                raise ValueError("Production requires HTTPS OIDC issuer and JWKS URL")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
