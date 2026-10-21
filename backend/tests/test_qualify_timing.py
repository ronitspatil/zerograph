import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from timing import arm_order, best_window, paired, phase_floor  # noqa: E402


def test_arm_order_is_abba():
    assert arm_order(1) == [("without", "with")]
    assert arm_order(4) == [
        ("without", "with"),
        ("with", "without"),
        ("without", "with"),
        ("with", "without"),
    ]
    assert arm_order(2, "a", "b") == [("a", "b"), ("b", "a")]


def test_paired_median_ignores_one_slow_run():
    # One "without" run hit a slow period (+9 s): min-of-arms and mean are both moved
    # by it, the median of paired differences is not.
    without = [16.0, 25.0, 16.2]
    with_ = [19.1, 19.3, 19.0]
    result = paired(without, with_)
    assert result["deltas"] == [3.1, -5.7, 2.8]
    assert result["median"] == 2.8
    assert (result["min"], result["max"]) == (-5.7, 3.1)


def test_paired_median_keeps_a_regression_present_in_every_pair():
    without = [16.0, 25.0, 16.2]
    regressed = [b + 2 for b in [19.1, 19.3, 19.0]]
    assert paired(without, regressed)["median"] == pytest.approx(4.8)


def test_paired_rejects_unpaired_runs():
    with pytest.raises(ValueError):
        paired([1.0], [1.0, 2.0])
    with pytest.raises(ValueError):
        paired([], [])


def test_best_window_stops_at_first_pass():
    windows = iter([{"p95": 700}, {"p95": 300}, {"p95": 200}])
    result = best_window(lambda: next(windows), lambda w: w["p95"] < 500, lambda w: w["p95"])
    assert result["passed"] is True
    assert result["best"] == {"p95": 300}
    assert result["windows"] == [{"p95": 700}, {"p95": 300}]


def test_best_window_reports_the_best_failing_window():
    windows = iter([{"p95": 700}, {"p95": 600}, {"p95": 650}, {"p95": 100}])
    result = best_window(lambda: next(windows), lambda w: w["p95"] < 500, lambda w: w["p95"])
    assert result["passed"] is False
    assert result["best"] == {"p95": 600}
    assert len(result["windows"]) == 3
    with pytest.raises(ValueError):
        best_window(dict, lambda w: True, lambda w: 0, windows=0)


def test_phase_floor_ignores_contended_runs_but_keeps_a_regression():
    phases = ("load", "compute", "store")
    without = [{"compute": 1.0, "store": 1.3}, {"compute": 2.9, "store": 2.2}]
    with_ = [{"load": 0.5, "compute": 2.1, "store": 3.4}, {"load": 1.4, "compute": 6.0, "store": 3.6}]
    floor = phase_floor(without, with_, phases)
    assert floor["phases"] == {"load": 0.5, "compute": 1.1, "store": 2.1}
    assert floor["total"] == 3.7
    slower = [{**run, "compute": run["compute"] + 2} for run in with_]
    assert phase_floor(without, slower, phases)["total"] == 5.7
    with pytest.raises(ValueError):
        phase_floor([], with_, phases)
