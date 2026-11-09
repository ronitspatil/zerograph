"""Docker Compose: each service is a non-human identity."""

from __future__ import annotations

import os

from ..loader import line_of
from ..model import LLM_KEYS, Graph, is_credential_name

ESCAPE_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_RAWIO"}


def parse(doc: dict, g: Graph, rel: str, abspath: str) -> None:
    project = str(doc.get("name") or os.path.basename(os.path.dirname(abspath)) or "compose")
    services = doc.get("services")
    if not isinstance(services, dict):
        g.warn(f"{rel}: no 'services' mapping, skipped")
        return
    for name in doc.get("secrets") or {}:
        g.add_node(_secret_id(project, name), "secret", f"{name} (compose secret)", 5,
                   rel, line_of(doc["secrets"], name), source="compose secret")
    networks: dict[str, list[tuple[str, int | None]]] = {}
    for name, svc in services.items():
        if not isinstance(svc, dict):
            g.warn(f"{rel}: service {name!r} is not a mapping, skipped")
            continue
        _service(g, project, str(name), svc, rel, line_of(services, name), abspath, networks)
    for net, members in networks.items():
        net_id = f"net:compose:{project}/{net}"
        g.add_node(net_id, "resource", f"network {net} ({project})", 2)
        for member, line in members:
            g.add_edge(member, net_id, "attached to", rel, line)
            for other, other_line in members:
                if other != member:
                    g.add_edge(net_id, other, "can reach", rel, other_line, transitive=False)


def _service(g, project, name, svc, rel, line, abspath, networks) -> None:
    sid = f"compose:{project}/{name}"
    labels = _as_mapping(svc.get("labels"))
    g.add_node(sid, "identity", f"{name} (compose)", 0, rel, line, platform="docker-compose",
               image=svc.get("image"),
               _aliases=[f"compose:{name}", f"compose:{project}/{name}"])
    node = g.nodes[sid]

    def at(key):
        return line_of(svc, key) or line

    if svc.get("privileged") is True:
        g.add_edge(sid, g.capability("host:root"), "privileged", rel, at("privileged"))
    for cap in svc.get("cap_add") or []:
        cap = str(cap).upper().removeprefix("CAP_")
        if cap in ESCAPE_CAPS:
            g.add_edge(sid, g.capability("host:root"), f"cap_add {cap}", rel, at("cap_add"))
        else:
            node.attrs.setdefault("cap_add", []).append(cap)
    if svc.get("network_mode") == "host":
        g.add_edge(sid, g.capability("host:network"), "network_mode: host", rel, at("network_mode"))
    if svc.get("pid") == "host":
        g.add_edge(sid, g.capability("host:pid"), "pid: host", rel, at("pid"))
    for vol in svc.get("volumes") or []:
        source, read_only = _bind_source(vol)
        if source:
            g.add_edge(sid, g.host_path(source, read_only), "mounts", rel, at("volumes"))

    env = svc.get("environment") or {}
    pairs = env.items() if isinstance(env, dict) else (
        (str(e).split("=", 1)[0], str(e).split("=", 1)[1] if "=" in str(e) else None) for e in env)
    agent_hint = labels.get("zerograph.agent") in ("true", True)
    for key, value in pairs:
        if key in LLM_KEYS:
            agent_hint = True
        if is_credential_name(key):
            inline = value is not None and "${" not in str(value) and str(value) != ""
            g.add_edge(sid, g.env_secret(key, rel, at("environment"), inline), "holds", rel,
                       at("environment"))
    for ref in svc.get("secrets") or []:
        secret = ref.get("source") if isinstance(ref, dict) else ref
        sec_id = _secret_id(project, secret)
        g.add_node(sec_id, "secret", f"{secret} (compose secret)", 5, rel, at("secrets"),
                   source="compose secret")
        g.add_edge(sid, sec_id, "holds", rel, at("secrets"))
    if agent_hint:
        node.attrs["_agent_hint"] = True

    build = svc.get("build")
    context = build.get("context") if isinstance(build, dict) else build
    if isinstance(context, str) and "://" not in context:
        node.attrs["_build_context"] = os.path.normpath(
            os.path.join(os.path.dirname(abspath), context))

    if svc.get("network_mode") is None:
        nets = svc.get("networks") or ["default"]
        for net in (nets if isinstance(nets, list) else list(nets)):
            networks.setdefault(str(net), []).append((sid, at("networks")))


def _secret_id(project, name) -> str:
    return f"secret:compose:{project}/{name}"


def _as_mapping(value) -> dict:
    if isinstance(value, dict):
        return value
    out = {}
    for item in value or []:
        key, _, val = str(item).partition("=")
        out[key] = val
    return out


def _bind_source(vol) -> tuple[str | None, bool]:
    """Return (host path, read_only) for a bind mount, or (None, False) for a named volume."""
    if isinstance(vol, dict):
        if vol.get("type") != "bind":
            return None, False
        return str(vol.get("source") or ""), bool(vol.get("read_only"))
    parts = str(vol).split(":")
    if len(parts) < 2 or not parts[0].startswith(("/", ".", "~", "$")):
        return None, False
    return parts[0], len(parts) > 2 and "ro" in parts[2].split(",")
