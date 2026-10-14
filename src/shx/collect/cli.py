"""shx-collect: read every server in an environment, without copying files off them.

    shx-collect environments/acme.toml --dry-run
    shx-collect environments/acme.toml --check
    shx-collect environments/acme.toml

Phase 1 (every server): a summary — app versions and fingerprints, Splunk service, and btool
for instance-level confs. Phase 2 (only servers holding apps whose copies differ): the
redacted conf values of those apps. Both phases print JSON on the server's stdout and exit;
nothing is written on the server.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import secrets
import shlex
import subprocess
import sys
from pathlib import Path

from shx.apps import differing_apps
from shx.collect.environment import EnvironmentError_, Server, load

REMOTE_SCRIPT = Path(__file__).resolve().parent.parent / "remote" / "collect_remote.py"


def remote_command(server: Server, mode: str = "summary", apps: list[str] = ()) -> str:
    home = shlex.quote(server.splunk_home)
    args = ["--splunk-home", home, f"--{mode}"]
    if mode == "summary" and not server.btool:
        args.append("--no-btool")
    for pattern in server.local_only_apps:
        args += ["--vendor-app", shlex.quote(pattern)]
    for app in apps:
        args += ["--app", shlex.quote(app)]
    # -B: never write __pycache__/*.pyc; nothing may be left behind on the server.
    python = f"{home}/bin/splunk cmd python3" if server.interpreter == "splunk" else "python3"
    cmd = f"{python} -B - {' '.join(args)}"
    if server.run_as:
        cmd = f"sudo -n -u {shlex.quote(server.run_as)} {cmd}"
    return cmd


def ssh_auth_options(server: Server) -> list[str]:
    if server.ssh_auth == "password":
        # ssh asks on the terminal (/dev/tty), so stdin stays free for the streamed script.
        return ["-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
    opts = [] if "BatchMode=yes" in server.ssh_options else ["-o", "BatchMode=yes"]
    if server.ssh_key:
        opts += ["-i", os.path.expanduser(server.ssh_key), "-o", "IdentitiesOnly=yes"]
    return opts


def ssh_destination(server: Server) -> str:
    if server.ssh_destination:
        return server.ssh_destination.format(host=server.host, user=server.ssh_user or "")
    return f"{server.ssh_user}@{server.host}" if server.ssh_user else server.host


def ssh_argv(server: Server, mode: str = "summary", apps: list[str] = ()) -> list[str]:
    target = ssh_destination(server)
    return ["ssh", "-T", *ssh_auth_options(server), *server.ssh_options, target,
            remote_command(server, mode, apps)]


def script_payload(salt: str) -> bytes:
    # Salt is prepended to the script body rather than passed as an argument, so it never
    # appears in the target's process list and is never written anywhere.
    return f'_INJECTED_SALT = "{salt}"\n'.encode() + REMOTE_SCRIPT.read_bytes()


def run_remote(server: Server, mode: str, salt: str, apps: list[str] = (), timeout: int | None = None) -> dict:
    """Run the remote script once; return {"ok", "data"|"error", "stderr"}."""
    try:
        proc = subprocess.run(ssh_argv(server, mode, apps), input=script_payload(salt),
                              capture_output=True, timeout=timeout or server.timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout or server.timeout_seconds}s", "stderr": ""}
    stderr = proc.stderr.decode(errors="replace")[-4000:]
    if proc.returncode != 0:
        return {"ok": False, "error": f"ssh exit {proc.returncode}", "stderr": stderr}
    lines = proc.stdout.decode(errors="replace").strip().splitlines()
    try:
        return {"ok": True, "data": json.loads(lines[-1]), "stderr": stderr}
    except (ValueError, IndexError):
        return {"ok": False, "error": "no JSON on stdout", "stderr": stderr}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-collect", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("environment", help="path to environments/<name>.toml")
    parser.add_argument("--only", help="comma-separated server names")
    parser.add_argument("--check", action="store_true", help="connectivity/permission check only")
    parser.add_argument("--dry-run", action="store_true", help="print what would run, do nothing")
    parser.add_argument("--out", default="snapshots", help="snapshot root directory")
    args = parser.parse_args(argv)

    try:
        env = load(args.environment)
        only = set(args.only.split(",")) if args.only else None
        servers = env.ordered(only)
    except (EnvironmentError_, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        for s in servers:
            print(f"# {s.name} ({'+'.join(s.roles)}{', ' + s.ha_group if s.ha_group else ''})")
            print(shlex.join(ssh_argv(s, "check" if args.check else "summary")))
        print("# phase 2 (--detail) runs only on servers holding apps whose copies differ")
        return 0

    if args.check:
        results = {}
        for s in servers:
            r = run_remote(s, "check", "", timeout=120)
            results[s.name] = {"ok": True, **r["data"]} if r["ok"] else \
                {"ok": False, "error": r["error"], "stderr": r["stderr"]}
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0 if all(r["ok"] for r in results.values()) else 1

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.out) / env.name / run_id
    run_dir.mkdir(parents=True)
    salt = secrets.token_hex(16)  # in memory only; never persisted (ADR-0001)
    run = {
        "environment": env.name, "run_id": run_id,
        "remote_script_sha256": hashlib.sha256(REMOTE_SCRIPT.read_bytes()).hexdigest(),
        "exclude_apps": list(env.exclude_apps),
        "servers": {s.name: {"role": s.role, "site": s.site, "ha_group": s.ha_group, "host": s.host,
                             "also_roles": list(s.also_roles)} for s in servers},
    }

    def save():
        (run_dir / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True))

    def log(server, msg):
        print(f"[{server}] {msg}", file=sys.stderr, flush=True)

    summaries, ok = {}, True
    for s in servers:  # phase 1, strictly sequential (ADR-0001)
        log(s.name, f"summary from {s.host} ...")
        r = run_remote(s, "summary", salt)
        entry = run["servers"][s.name]
        if r["ok"]:
            (run_dir / f"{s.name}.summary.json").write_text(json.dumps(r["data"], indent=1, sort_keys=True))
            summaries[s.name] = r["data"]
            entry.update(ok=True, summary=f"{s.name}.summary.json", apps=len(r["data"].get("apps", [])),
                         errors=len(r["data"].get("errors", [])))
            log(s.name, f"ok ({entry['apps']} apps)")
        else:
            ok = False
            entry.update(ok=False, error=r["error"], stderr=r["stderr"][-1000:])
            log(s.name, f"FAILED: {r['error']}")
        save()

    wanted = differing_apps(summaries, env.exclude_apps)
    by_name = {s.name: s for s in servers}
    for name in [s.name for s in servers if s.name in wanted]:  # phase 2, same order
        s = by_name[name]
        log(name, f"detail for {len(wanted[name])} differing apps ...")
        r = run_remote(s, "detail", salt, wanted[name])
        entry = run["servers"][name]
        if r["ok"]:
            (run_dir / f"{name}.detail.json").write_text(json.dumps(r["data"], indent=1, sort_keys=True))
            entry.update(detail=f"{name}.detail.json", detail_apps=len(wanted[name]))
            log(name, "ok")
        else:
            ok = False
            entry.update(detail_error=r["error"])
            log(name, f"detail FAILED: {r['error']}")
        save()
    save()
    print(run_dir)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
