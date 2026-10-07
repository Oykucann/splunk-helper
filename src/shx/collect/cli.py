"""shx-collect: collect read-only snapshots from every server in an environment.

    shx-collect environments/acme.toml --check
    shx-collect environments/acme.toml --only hf-pull01
    shx-collect environments/acme.toml
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import secrets
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

from shx.collect import rest_collect
from shx.collect.environment import EnvironmentError_, Server, load
from shx.collect.searches import SEARCHES
from shx.transport.rest import RestError

REMOTE_SCRIPT = Path(__file__).resolve().parent.parent / "remote" / "collect_remote.py"
GZIP_MAGIC = b"\x1f\x8b"


def remote_command(server: Server, check: bool) -> str:
    home = shlex.quote(server.splunk_home)
    args = ["--splunk-home", home]
    if check:
        args.append("--check")
    if not server.btool:
        args.append("--no-btool")
    for pattern in server.local_only_apps:
        args += ["--local-only-app", shlex.quote(pattern)]
    cmd = f"{home}/bin/splunk cmd python3 - {' '.join(args)}"
    if server.run_as:
        cmd = f"sudo -n -u {shlex.quote(server.run_as)} {cmd}"
    return cmd


def ssh_argv(server: Server, check: bool) -> list[str]:
    target = f"{server.ssh_user}@{server.host}" if server.ssh_user else server.host
    return ["ssh", "-T", *server.ssh_options, target, remote_command(server, check)]


def script_payload(salt: str) -> bytes:
    # Salt is prepended to the script body rather than passed as an argument, so it never
    # appears in the target's process list and is never written anywhere.
    return f'_INJECTED_SALT = "{salt}"\n'.encode() + REMOTE_SCRIPT.read_bytes()


def validate_snapshot(path: Path) -> dict:
    with path.open("rb") as fh:
        if fh.read(2) != GZIP_MAGIC:
            raise ValueError("output is not gzip (remote printed something else to stdout?)")
    with tarfile.open(path, "r:gz") as tar:
        member = tar.getmember("manifest.json")
        manifest = json.load(tar.extractfile(member))
    return {
        "hostname": manifest.get("hostname"),
        "splunk_version": manifest.get("splunk_version"),
        "files": len(manifest.get("files", [])),
        "redactions": manifest.get("redactions"),
        "errors": len(manifest.get("errors", [])),
    }


def run_check(server: Server) -> dict:
    proc = subprocess.run(
        ssh_argv(server, check=True), input=script_payload(""),
        capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        return {"ok": False, "stderr": proc.stderr.decode(errors="replace")[-2000:]}
    try:
        return {"ok": True, **json.loads(proc.stdout.decode().strip().splitlines()[-1])}
    except (ValueError, IndexError):
        return {"ok": False, "stdout": proc.stdout.decode(errors="replace")[-2000:]}


def collect_one(server: Server, run_dir: Path, salt: str) -> dict:
    final = run_dir / f"{server.name}.tar.gz"
    partial = final.with_suffix(".gz.partial")
    log_path = run_dir / f"{server.name}.stderr.log"
    with partial.open("wb") as out, log_path.open("wb") as err:
        proc = subprocess.Popen(ssh_argv(server, check=False), stdin=subprocess.PIPE,
                                stdout=out, stderr=err)
        try:
            proc.communicate(script_payload(salt), timeout=server.timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return {"ok": False, "error": f"timeout after {server.timeout_seconds}s"}
    if proc.returncode != 0:
        return {"ok": False, "error": f"ssh exit {proc.returncode}, see {log_path.name}"}
    try:
        summary = validate_snapshot(partial)
    except (ValueError, KeyError, tarfile.TarError) as exc:
        return {"ok": False, "error": f"invalid snapshot: {exc}"}
    partial.rename(final)
    return {"ok": True, "snapshot": final.name, **summary}


def rest_check(server: Server, env) -> dict:
    try:
        ctx = rest_collect.check_context(rest_collect.client_for(server), server)
    except (rest_collect.RestRefused, RestError, OSError) as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "username": ctx["username"], "roles": ctx["roles"],
            "privileged_capabilities": ctx["privileged_capabilities"]}


def rest_one(server: Server, env, run_dir: Path) -> dict:
    try:
        result = rest_collect.collect(server, env)
    except (rest_collect.RestRefused, RestError, OSError, KeyError) as exc:
        return {"ok": False, "error": str(exc)}
    (run_dir / f"{server.name}.rest.json").write_text(json.dumps(result, indent=1, sort_keys=True))
    return {"file": f"{server.name}.rest.json", **rest_collect.summary(result)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-collect", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("environment", help="path to environments/<name>.toml")
    parser.add_argument("--only", help="comma-separated server names")
    parser.add_argument("--check", action="store_true", help="connectivity/permission check only")
    parser.add_argument("--dry-run", action="store_true", help="print what would run, do nothing")
    parser.add_argument("--out", default="snapshots", help="snapshot root directory")
    part = parser.add_mutually_exclusive_group()
    part.add_argument("--no-rest", action="store_true", help="SSH collection only")
    part.add_argument("--rest-only", action="store_true", help="search-head REST collection only")
    args = parser.parse_args(argv)

    try:
        env = load(args.environment)
        only = set(args.only.split(",")) if args.only else None
        servers = env.ordered(only)
    except (EnvironmentError_, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    ssh_servers = [] if args.rest_only else servers
    rest_servers = [] if args.no_rest else [s for s in servers if s.rest_enabled]

    if args.dry_run:
        for s in ssh_servers:
            print(f"# {s.name} ({'+'.join(s.roles)}{', ' + s.ha_group if s.ha_group else ''})")
            print(shlex.join(ssh_argv(s, check=args.check)))
        for s in rest_servers:
            print(f"# {s.name} REST {s.rest_scheme}://{s.host}:{s.rest_port} "
                  f"searches: indexes, {', '.join(x.id for x in SEARCHES)}")
        return 0

    if args.check:
        results = {s.name: {"ssh": run_check(s)} for s in ssh_servers}
        for s in rest_servers:
            results.setdefault(s.name, {})["rest"] = rest_check(s, env)
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0 if all(r["ok"] for parts in results.values() for r in parts.values()) else 1

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.out) / env.name / run_id
    run_dir.mkdir(parents=True)
    salt = secrets.token_hex(16)  # in memory only; never persisted (ADR-0001)
    run = {
        "environment": env.name,
        "run_id": run_id,
        "remote_script_sha256": hashlib.sha256(REMOTE_SCRIPT.read_bytes()).hexdigest(),
        "servers": {s.name: {"role": s.role, "site": s.site, "ha_group": s.ha_group, "host": s.host,
                             "pull_apps": list(s.pull_apps), "also_roles": list(s.also_roles)}
                    for s in {*ssh_servers, *rest_servers}},
    }

    def save():
        (run_dir / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True))

    outcomes = []
    for s in ssh_servers:  # strictly sequential (ADR-0001)
        print(f"[{s.name}] collecting from {s.host} ...", file=sys.stderr, flush=True)
        result = collect_one(s, run_dir, salt)
        run["servers"][s.name].update(result)
        outcomes.append(result["ok"])
        print(f"[{s.name}] {'ok' if result['ok'] else 'FAILED: ' + result['error']}",
              file=sys.stderr, flush=True)
        save()
    for s in rest_servers:
        print(f"[{s.name}] REST searches on {s.host} ...", file=sys.stderr, flush=True)
        result = rest_one(s, env, run_dir)
        run["servers"][s.name]["rest"] = result
        outcomes.append(result["ok"])
        status = "ok" if result["ok"] else "FAILED: " + (result.get("error") or ", ".join(result["failed"]))
        print(f"[{s.name}] REST {status}", file=sys.stderr, flush=True)
        save()
    save()
    print(run_dir)
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
