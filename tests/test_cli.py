import json
import os

from zerograph.cli import main

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")
PLANTED = ["example-not-a-real-password", "placeholder-value-never-shown", "bm90LWEtcmVhbC1wYXNzd29yZA",
           "ghp_placeholderNotARealToken", "hunter2"]


def test_scan_examples_writes_html_and_json(tmp_path, capsys):
    html, js = tmp_path / "zg.html", tmp_path / "zg.json"
    assert main(["scan", EXAMPLES, "-o", str(html), "--json", str(js)]) == 0
    out = capsys.readouterr().out
    assert "support_agent" in out and "critical" in out

    data = json.loads(js.read_text())
    ranked = [a["label"] for a in data["agents"]]
    assert ranked[0].startswith("support_agent")
    assert len(ranked) == 5
    assert all(a["findings"] for a in data["agents"])

    page = html.read_text()
    assert "cytoscape/3.30.2/cytoscape.min.js" in page and 'integrity="sha384-' in page
    assert "__DATA__" not in page and "</script><" not in page.split('id="data"')[1].split("</script>")[0]
    for value in PLANTED:
        assert value not in page and value not in js.read_text(), value


def test_missing_path(capsys):
    assert main(["scan", "/definitely/not/here"]) == 2
