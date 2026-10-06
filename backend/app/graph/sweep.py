"""Bounded worker sweeps that bring current revisions up to date in the background.

A sweep finds (tenant, current revision) pairs that lack a derived artifact of
the current version (global-map clusters, the explore sample) with one SQL query
and backfills at most ``limit`` tenants per run, each in its own transaction under
the tenant's publication lock taken without waiting: a tenant that is publishing
is skipped (its publication stores the artifact anyway) instead of queueing a
worker behind it. A tenant whose backfill fails is logged and not retried by the
same process for ``FAILED_BACKOFF_SECONDS``; one tenant's failure never stops the
sweep.
"""

import time
from collections.abc import Callable

from loguru import logger

SWEEP_TENANTS = 3
FAILED_BACKOFF_SECONDS = 3600


def run_sweep(
    label: str,
    pending: Callable[[int], list[tuple[str, str]]],
    backfill: Callable[[str], dict],
    failed: dict[tuple[str, str], float],
    describe: Callable[[dict], str],
    limit: int = SWEEP_TENANTS,
    backoff: float = FAILED_BACKOFF_SECONDS,
) -> list[dict]:
    """Backfill up to ``limit`` pending tenants; ``failed`` is the caller's per-process backoff map.

    ``pending(n)`` returns at most ``n`` (tenant, current revision) pairs in a stable order.

    ``backfill(tenant)`` must not wait for the publication lock: it returns
    ``{"busy": True, ...}`` when the lock is held, and ``"backfilled"`` otherwise.
    """
    clock = time.monotonic()
    candidates = pending(limit + len(failed))
    results = []
    for tenant, revision in candidates:
        failed_at = failed.get((tenant, revision))
        if failed_at is not None and clock - failed_at < backoff:
            continue
        if len(results) >= limit:
            break
        try:
            result = backfill(tenant)
        except Exception as exc:  # noqa: BLE001 - one tenant must not stop the sweep
            failed[(tenant, revision)] = clock
            logger.warning(
                "{} backfill failed tenant={} revision={} exception_type={}",
                label,
                tenant,
                revision,
                type(exc).__name__,
            )
            result = {"tenant": tenant, "revision": revision, "backfilled": False, "failed": True}
        else:
            failed.pop((tenant, revision), None)
            if result.get("backfilled"):
                logger.info(
                    "{} backfill stored tenant={} revision={} {}",
                    label,
                    tenant,
                    result["revision"],
                    describe(result),
                )
        results.append(result)
    return results
