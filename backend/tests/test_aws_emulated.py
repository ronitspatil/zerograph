"""The real AWS collector end to end against a local AWS emulator (moto server on 127.0.0.1).

Runs ``scripts/qualify_aws_emulated.py`` as a subprocess (it sets the SDK endpoint and
ZeroGraph settings for its own process only). No real AWS account or network is used.
"""

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("moto")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "qualify_aws_emulated.py"


def free_port() -> int:
    for port in range(55551, 55560):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) != 0:
                return port
    pytest.skip("No free emulator port in 55551-55559")


def test_collector_publishes_an_emulated_account_end_to_end(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(tmp_path), "--port", str(free_port())],
        capture_output=True,
        text=True,
        timeout=600,
    )
    report = json.loads((tmp_path / "aws-emulated.json").read_text())
    assert result.returncode == 0, [failure["check"] for failure in report["failures"]]
    names = {check["check"] for check in report["checks"]}
    assert {
        "aws job completed",
        "the cross-topic over-grant is a high-tier remove_grant",
        "lake formation modes resolved",
        "scp deny removes s3:DeleteObject from write edges",
    } <= names
    # Emulator differences are recorded apart from failures.
    assert any(item["api"] == "iam:GenerateServiceLastAccessedDetails" for item in report["moto_gaps"])
