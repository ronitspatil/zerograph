from conftest import targets

COMPOSE = """\
name: demo
services:
  web:
    image: nginx
    networks: [front, back]
  worker:
    image: worker
    privileged: true
    pid: host
    cap_add: [NET_ADMIN, SYS_ADMIN]
    networks: [back]
    environment:
      - API_TOKEN=abc123
      - LOG_LEVEL=info
    secrets: [db_pw]
  sidecar:
    image: busybox
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc:ro
      - named:/data
      - type: bind
        source: /
        target: /host
  bot:
    build: ./bot
    environment:
      OPENAI_API_KEY: ${OPENAI_API_KEY}
secrets:
  db_pw:
    file: ./pw.txt
"""


def test_services_and_dangerous_settings(scan_files):
    g = scan_files({"docker-compose.yml": COMPOSE})
    worker = "compose:demo/worker"
    assert g.nodes[worker].kind == "identity"
    assert {"cap:host:root", "cap:host:pid"} <= targets(g, worker)
    assert g.nodes[worker].attrs["cap_add"] == ["NET_ADMIN"]
    assert "secret:env:API_TOKEN" in targets(g, worker)
    assert "secret:env:LOG_LEVEL" not in g.nodes
    assert "secret:compose:demo/db_pw" in targets(g, worker)
    sidecar = targets(g, "compose:demo/sidecar")
    assert {"cap:host:network", "cap:host:docker", "hostpath:ro:/etc", "cap:host:root"} <= sidecar
    assert not any("named" in t for t in sidecar)


def test_line_numbers_point_at_the_setting(scan_files):
    g = scan_files({"docker-compose.yml": COMPOSE})
    edge = next(e for e in g.edges if e.src == "compose:demo/worker" and e.rel == "privileged")
    assert (edge.file, edge.line) == ("docker-compose.yml", 8)
    assert g.nodes["compose:demo/worker"].line == 6


def test_shared_networks_are_reachable_but_not_transitive(scan_files):
    g = scan_files({"docker-compose.yml": COMPOSE})
    back = "net:compose:demo/back"
    assert back in targets(g, "compose:demo/web")
    reach = [e for e in g.edges if e.src == back]
    assert {e.dst for e in reach} == {"compose:demo/web", "compose:demo/worker"}
    assert not any(e.transitive for e in reach)


def test_llm_key_marks_service_as_agent(scan_files):
    g = scan_files({"docker-compose.yml": COMPOSE})
    assert g.nodes["agent:compose:demo/bot"].kind == "agent"
    assert "compose:demo/bot" in targets(g, "agent:compose:demo/bot")


def test_inline_secret_value_is_flagged_but_never_stored(scan_files):
    g = scan_files({"compose.yaml": COMPOSE})
    node = g.nodes["secret:env:API_TOKEN"]
    assert node.attrs["inline_value_found"] is True
    assert "abc123" not in repr(node)
