from zerograph.scan import scan


def test_malformed_and_unknown_inputs_warn_instead_of_crashing(scan_files):
    g = scan_files({
        "bad.yaml": "key: [unclosed\n  - nope: : :\n",
        "docker-compose.yml": "services: [not, a, mapping]\n",
        "bad.json": "{not json",
        "odd.yaml": "- just\n- a list\n",
        "crd.yaml": "apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: w}\n",
        "nulls.yaml": "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n---\n---\n",
        "evil.yaml": "x: !!python/object/apply:os.system ['echo pwned']\n",
        "compose.weird.yml": "services:\n  a: 5\n  b:\n    environment: [FOO]\n    volumes: [null]\n",
        "binary.yml": "\x00\x01\x02",
        "notes.txt": "ignored",
    })
    text = "\n".join(g.warnings)
    assert "bad.yaml: invalid YAML" in text
    assert "bad.json: invalid JSON" in text
    assert "evil.yaml" in text  # unsafe tags are refused by SafeLoader
    assert "unsupported Kubernetes kinds: Widget x1" in text
    assert "docker-compose.yml: no 'services' mapping" in text
    assert "service 'a' is not a mapping" in text
    assert "k8s:sa:default/?" in g.nodes


def test_single_file_and_empty_dir(tmp_path):
    (tmp_path / "compose.yml").write_text("services:\n  a:\n    privileged: true\n")
    g = scan(str(tmp_path / "compose.yml"))
    assert any(n.endswith("/a") for n in g.nodes)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert not scan(str(empty)).nodes


def test_skips_vendored_directories(scan_files):
    g = scan_files({"node_modules/pkg/mcp.json": '{"mcpServers": {"x": {"command": "bash"}}}'})
    assert not g.nodes
