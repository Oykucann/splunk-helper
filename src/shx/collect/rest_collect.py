"""Run the SPEC-002 search catalog against one search head."""

from __future__ import annotations

import os
from pathlib import Path

from shx.collect.environment import Environment, Server
from shx.collect.searches import SEARCHES, indexes_search
from shx.transport.rest import GuardError, RestClient, RestError, mask_text, privileged


class RestRefused(RuntimeError):
    pass


def load_token(server: Server) -> str:
    if server.rest_token_env:
        token = os.environ.get(server.rest_token_env, "")
        if not token:
            raise RestRefused(f"environment variable {server.rest_token_env} is empty")
        return token.strip()
    path = Path(os.path.expanduser(server.rest_token_file))
    return path.read_text().strip()


def client_for(server: Server) -> RestClient:
    return RestClient(base_url=f"{server.rest_scheme}://{server.host}:{server.rest_port}",
                      token=load_token(server), verify_tls=server.rest_verify_tls,
                      ca_file=server.rest_ca_file)


def hf_identifiers(env: Environment) -> set[str]:
    ids = set()
    for s in env.servers:
        if s.role == "hf":
            ids |= {s.name.lower(), s.host.lower()}
    return ids


def split_peers(peers_payload: dict, hf_ids: set[str]) -> tuple[list[dict], list[dict]]:
    allowed, excluded = [], []
    for entry in peers_payload.get("entry", []):
        content = entry.get("content", {})
        peer = {"name": content.get("peerName") or entry.get("name"),
                "host": (entry.get("name") or "").split(":")[0],
                "roles": content.get("server_roles", []), "status": content.get("status")}
        candidates = {str(peer["name"]).lower(), peer["host"].lower()}
        (excluded if candidates & hf_ids else allowed).append(peer)
    return allowed, excluded


def check_context(client: RestClient, server: Server) -> dict:
    ctx = client.current_context()
    ctx["privileged_capabilities"] = privileged(ctx["capabilities"])
    if ctx["privileged_capabilities"] and not server.allow_privileged_token:
        raise RestRefused(
            "token has write/admin capabilities "
            f"({', '.join(ctx['privileged_capabilities'][:8])}); use a read-only role "
            "or set allow_privileged_token = true for lab servers")
    return ctx


def _mask_results(results: list[dict]) -> list[dict]:
    return [{k: mask_text(v) if isinstance(v, str) else v for k, v in row.items()} for row in results]


def run_search(client: RestClient, search_id: str, spl: str, earliest: str | None) -> dict:
    record = {"spl": spl, "earliest": earliest, "ok": False}
    try:
        payload = client.oneshot(spl, earliest=earliest)
    except (RestError, GuardError, ValueError) as exc:
        record["error"] = str(exc)
        return record
    messages = payload.get("messages", [])
    record.update(ok=not any(m.get("type") in ("FATAL", "ERROR") for m in messages),
                  results=_mask_results(payload.get("results", [])),
                  messages=messages, seconds=payload.get("_seconds"))
    return record


def collect(server: Server, env: Environment, client: RestClient | None = None) -> dict:
    client = client or client_for(server)
    out: dict = {"context": check_context(client, server), "searches": {}}
    info = client.get("/services/server/info")["entry"][0]["content"]
    out["server_info"] = {k: info.get(k) for k in ("serverName", "version", "server_roles", "guid", "os_name")}

    peers_payload = client.get("/services/search/distributed/peers")
    allowed, excluded = split_peers(peers_payload, hf_identifiers(env))
    out["search_peers"] = {"allowed": allowed, "excluded_hf": excluded}
    peer_names = None if not excluded else [p["name"] for p in allowed]

    out["searches"]["indexes"] = run_search(client, "indexes", indexes_search(peer_names), None)
    for s in SEARCHES:
        out["searches"][s.id] = run_search(client, s.id, s.spl, s.earliest)
    return out


def summary(result: dict) -> dict:
    searches = result.get("searches", {})
    return {"ok": all(s["ok"] for s in searches.values()),
            "failed": sorted(k for k, s in searches.items() if not s["ok"]),
            "excluded_hf_peers": [p["name"] for p in result.get("search_peers", {}).get("excluded_hf", [])]}
