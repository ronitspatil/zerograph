"""Noise-robust timing comparisons shared by the qualification scripts.

Wall-clock times on a shared machine drift by seconds between runs (other processes,
thermal state, Docker I/O), so comparing the fastest run of one arm with the fastest
run of another, or one p95 window against a fixed budget, fails on unchanged code. The
helpers here keep a real regression visible while absorbing that drift:

* ``arm_order``: interleave the two arms in ABBA order, so a slow period or a warming
  cache hits both arms equally instead of always the second one;
* ``paired``: per-pair differences (each "with" run against the "without" run next to
  it) and their median, which a single slow run cannot move. A regression that is
  present in every run still shifts every pair, so the median moves by its full size;
* ``phase_floor``: for work made of independent phases (load, compute, store), the
  fastest run of each phase per arm. Contention only ever adds time, and a phase lasts
  seconds, so with a few runs at least one of them is usually undisturbed; a
  regression adds its cost to every run and so to the fastest one too;
* ``best_window``: repeat a latency window when it misses its budget and gate on the
  best window, so a burst of contention cannot fail the check but a slow endpoint,
  which misses in every window, still does.
"""

import statistics
from collections.abc import Callable


def arm_order(pairs: int, first: str = "without", second: str = "with") -> list[tuple[str, str]]:
    """ABBA order: ``[(first, second), (second, first), (first, second), ...]``."""
    return [(first, second) if index % 2 == 0 else (second, first) for index in range(pairs)]


def paired(without: list[float], with_: list[float]) -> dict:
    """Pairwise differences ``with_[i] - without[i]`` and their median (seconds, rounded)."""
    if not without or len(without) != len(with_):
        raise ValueError("Paired timings need the same, non-zero number of runs per arm")
    deltas = [b - a for a, b in zip(without, with_, strict=True)]
    return {
        "deltas": [round(delta, 3) for delta in deltas],
        "median": round(statistics.median(deltas), 3),
        "min": round(min(deltas), 3),
        "max": round(max(deltas), 3),
    }


def phase_floor(without: list[dict], with_: list[dict], phases: tuple[str, ...]) -> dict:
    """Per phase, the fastest ``with_`` run minus the fastest ``without`` run (a phase a
    run did not perform counts 0), and their sum (seconds, rounded)."""
    if not without or not with_:
        raise ValueError("Each arm needs at least one run")
    delta = {
        phase: min(run.get(phase, 0.0) for run in with_) - min(run.get(phase, 0.0) for run in without)
        for phase in phases
    }
    return {"phases": {k: round(v, 3) for k, v in delta.items()}, "total": round(sum(delta.values()), 3)}


def best_window(
    measure: Callable[[], dict], passes: Callable[[dict], bool], score: Callable[[dict], float], windows: int = 3
) -> dict:
    """Run ``measure`` until a window ``passes`` or ``windows`` windows were measured.

    Returns ``{"passed", "best", "windows"}``: ``best`` is the passing window, or the
    lowest-``score`` window when none passed; ``windows`` lists every window measured.
    """
    if windows < 1:
        raise ValueError("At least one window is required")
    measured = []
    for _ in range(windows):
        measured.append(measure())
        if passes(measured[-1]):
            return {"passed": True, "best": measured[-1], "windows": measured}
    return {"passed": False, "best": min(measured, key=score), "windows": measured}
