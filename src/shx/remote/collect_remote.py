"""splunk-helper remote collector.

Streamed to a target over SSH and executed as:

    splunk cmd python3 - --splunk-home /opt/splunk [--no-btool] [--check]

READ-ONLY BY CONSTRUCTION (ADR-0001). This script must never create, modify or delete
files on the target, and must never talk to splunkd. It reads files, stats paths and
runs `splunk btool <conf> list --debug`. Everything it produces is written to stdout as
a tar.gz stream. tests/test_remote_guard.py enforces this; keep the code boring.

Compatible with Python 3.7 (Splunk's bundled interpreter) and the standard library only.
"""

import argparse
import fnmatch
import hashlib
import hmac
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tarfile
import time

SCHEMA_VERSION = 2

# Roots under $SPLUNK_HOME/etc. "active" roots are loaded by this instance's splunkd;
# the others are staged content pushed elsewhere (DS, CM, deployer).
SCAN_ROOTS = [
    ("system/local", True),
    ("apps", True),
    ("peer-apps", True),
    ("slave-apps", True),
    ("users", True),
    ("deployment-apps", False),
    ("manager-apps", False),
    ("master-apps", False),
    ("shcluster/apps", False),
]

APP_ROOTS = {"apps", "peer-apps", "slave-apps", "deployment-apps", "manager-apps",
             "master-apps", "shcluster/apps"}

# Large vendor / built-in apps: collect only default/app.conf, local/, metadata/ and the
# lookups/ index, plus a size summary. Their default/ content is stock and very large.
# Splunk_TA_ForIndexers and SplunkEnterpriseSecuritySuite's own local/ are still captured;
# extra patterns come from the environment file (--local-only-app).
DEFAULT_LOCAL_ONLY_APPS = [
    # Enterprise Security and its supporting apps
    "SplunkEnterpriseSecuritySuite", "DA-ESS-*", "SA-AccessProtection",
    "SA-AuditAndDataProtection", "SA-EndpointProtection", "SA-IdentityManagement",
    "SA-NetworkProtection", "SA-ThreatIntelligence", "SA-UEBA", "SA-Utils",
    "SA-TestModeControl", "SA-ContentVersioning", "SA-Detections", "Splunk_SA_CIM",
    "Splunk_ML_Toolkit", "Splunk_SA_Scientific_Python_*", "missioncontrol",
    "Splunk_TA_ueba", "splunk_essentials_*",
    # Splunk built-ins
    "search", "launcher", "learned", "legacy", "sample_app", "user-prefs", "appsbrowser",
    "introspection_generator_addon", "splunk_archiver", "splunk_instrumentation",
    "splunk_monitoring_console", "splunk_secure_gateway", "splunk_rapid_diag",
    "splunk_metrics_workspace", "splunk_httpinput", "splunk_internal_metrics", "splunk_gdi",
    "splunk_assist", "splunk-dashboard-studio", "python_upgrade_readiness_app",
    "journald_input", "alert_logevent", "alert_webhook", "SplunkForwarder",
    "SplunkLightForwarder", "SplunkDeploymentServerConfig", "splunk_ingest_actions",
    "splunk-visual-exporter",
]
LOCAL_ONLY_SUBDIRS = ("local", "metadata", "lookups")

COPY_EXTENSIONS = (".conf", ".meta")

BTOOL_CONFS = [
    "app", "authentication", "authorize", "datamodels", "deploymentclient", "distsearch",
    "eventtypes", "fields", "indexes", "inputs", "limits", "macros", "outputs", "props",
    "savedsearches", "server", "serverclass", "tags", "transforms", "web",
    "db_connections", "db_inputs", "identities", "health", "alert_actions",
]

SYSTEM_FILES = [
    ("/etc/keepalived/keepalived.conf", "system/keepalived.conf"),
    ("/etc/haproxy/haproxy.cfg", "system/haproxy.cfg"),
]

MAX_COPY_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 300 * 1024 * 1024
MAX_HASH_BYTES = 50 * 1024 * 1024
MAX_SCAN_BYTES = 1024 * 1024
BTOOL_TIMEOUT = 60

# --- redaction ----------------------------------------------------------------------

SECRET_KEY_RE = re.compile(
    r"(?i)^(.*pass(word|wd)?|.*secret.*|token|.*_token|.*authtoken|pass4symmkey"
    r"|.*api_?key|.*private_?key|.*access_?key|.*credentials?)$"
)
# Search-time / index-time class names may contain "password" but hold regexes, not secrets.
NOT_SECRET_KEY_RE = re.compile(
    r"(?i)^(extract|report|transforms|fieldalias|eval|lookup|sedcmd)-"
)
ENCRYPTED_RE = re.compile(r"\$\d\$[A-Za-z0-9+/=]{8,}")
CONF_KV_RE = re.compile(r"^(\s*#?\s*)([^=\[\s][^=]*?)(\s*=\s*)(.*?)(\s*)$")
SYSTEM_SECRET_RES = [
    re.compile(r"(?i)^(\s*auth_pass\s+)(\S+)"),
    re.compile(r"(?i)^(\s*stats\s+auth\s+[^:\s]+:)(\S+)"),
    re.compile(r"(?i)(\b(?:insecure-)?password\s+)(\S+)"),
]
SCRIPT_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*['\"]?([^\s'\"$%{]{4,})"
)


class Redactor(object):
    def __init__(self, salt):
        self.salt = salt.encode("utf-8") if salt else b""
        self.count = 0

    def mask(self, value):
        self.count += 1
        if not self.salt:
            return "<redacted>"
        digest = hmac.new(self.salt, value.encode("utf-8", "replace"), hashlib.sha256)
        return "<redacted:%s>" % digest.hexdigest()[:12]

    def _encrypted(self, text):
        return ENCRYPTED_RE.sub(lambda m: self.mask(m.group(0)), text)

    def conf_line(self, line, in_secret_continuation=False):
        """Redact one conf line. Returns (line, value_continues_as_secret)."""
        if in_secret_continuation:
            body = line.rstrip("\n")
            return self.mask(body) + ("\n" if line.endswith("\n") else ""), body.endswith("\\")
        m = CONF_KV_RE.match(line.rstrip("\n"))
        nl = "\n" if line.endswith("\n") else ""
        if m:
            prefix, key, sep, value, trail = m.groups()
            if value and SECRET_KEY_RE.match(key) and not NOT_SECRET_KEY_RE.match(key):
                return prefix + key + sep + self.mask(value) + trail + nl, value.endswith("\\")
        return self._encrypted(line), False

    def conf_text(self, text):
        out = []
        cont = False
        for line in text.splitlines(True):
            red, cont = self.conf_line(line, cont)
            out.append(red)
        return "".join(out)

    def btool_text(self, text):
        # btool --debug lines: "<source path><spaces><conf line>"
        out = []
        cont = False
        for line in text.splitlines(True):
            m = re.match(r"^(/\S+\s+|[A-Za-z]:\\\S+\s+)(.*)$", line, re.S)
            if m:
                red, cont = self.conf_line(m.group(2), cont)
                out.append(m.group(1) + red)
            else:
                red, cont = self.conf_line(line, cont)
                out.append(red)
        return "".join(out)

    def system_text(self, text):
        out = []
        for line in text.splitlines(True):
            for rx in SYSTEM_SECRET_RES:
                line = rx.sub(lambda m: m.group(1) + self.mask(m.group(2)), line)
            out.append(self._encrypted(line))
        return "".join(out)


# --- helpers ------------------------------------------------------------------------

def log(msg):
    sys.stderr.write("[collect_remote] %s\n" % msg)
    sys.stderr.flush()


def read_bytes(path, limit):
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def owner_name(uid):
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def classify(rel):
    parts = rel.split("/")
    if rel.endswith(COPY_EXTENSIONS):
        return "conf"
    if "bin" in parts:
        return "script"
    if "lookups" in parts:
        return "lookup"
    return "other"


def is_text(sample):
    return b"\x00" not in sample[:4096]


def scan_script_secrets(path):
    hits = []
    data = read_bytes(path, MAX_SCAN_BYTES)
    if not is_text(data):
        return hits
    for no, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        m = SCRIPT_SECRET_RE.search(line)
        if m:
            hits.append({"line": no, "key": m.group(1).lower()})
    return hits


STANZA_PATH_RE = re.compile(r"^\s*\[(monitor|script|batch)://(.+)\]\s*$")


def resolve_input_path(kind, raw, conf_path, splunk_home):
    path = raw.replace("$SPLUNK_HOME", splunk_home)
    if kind == "script" and not os.path.isabs(path):
        app_dir = os.path.dirname(os.path.dirname(conf_path))
        if path.startswith("./"):
            path = os.path.join(app_dir, path[2:])
        else:
            path = os.path.join(app_dir, "bin", path)
    cut = len(path)
    for token in ("*", "..."):
        idx = path.find(token)
        if idx != -1:
            cut = min(cut, idx)
    wildcard = cut < len(path)
    if wildcard:
        path = os.path.dirname(path[:cut])
    return path, wildcard


def input_path_checks(text, conf_path, rel, splunk_home):
    checks = []
    for line in text.splitlines():
        m = STANZA_PATH_RE.match(line)
        if not m:
            continue
        kind, raw = m.group(1), m.group(2).strip()
        resolved, wildcard = resolve_input_path(kind, raw, conf_path, splunk_home)
        exists = os.path.exists(resolved)
        if not exists and kind == "script" and " " in raw:
            resolved, wildcard = resolve_input_path(kind, raw.split()[0], conf_path, splunk_home)
            exists = os.path.exists(resolved)
        checks.append({
            "conf": rel, "stanza": "%s://%s" % (kind, raw), "kind": kind,
            "checked_path": resolved, "wildcard": wildcard, "exists": exists,
        })
    return checks


def _run_btool(splunk_home, conf):
    """The only subprocess call allowed in this file (see tests/test_remote_guard.py)."""
    exe = os.path.join(splunk_home, "bin", "splunk")
    proc = subprocess.run(
        [exe, "btool", conf, "list", "--debug"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=BTOOL_TIMEOUT,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def drop_stock_btool_lines(text, default_dirs):
    """Drop key lines sourced from a local-only app's default/ dir; keep stanza headers so
    local overrides stay attached to their stanza. Returns (text, dropped_count)."""
    if not default_dirs:
        return text, 0
    prefixes = tuple(default_dirs)
    out = []
    dropped = 0
    for line in text.splitlines(True):
        if line.startswith(prefixes):
            body = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            if not body.startswith("["):
                dropped += 1
                continue
        out.append(line)
    return "".join(out), dropped


class BudgetExceeded(Exception):
    pass


def is_local_part(inner):
    """Path inside an app that holds site customisations rather than shipped content."""
    return inner.startswith("local" + os.sep) or inner == os.path.join("metadata", "local.meta")


def fingerprint(items):
    h = hashlib.sha256()
    for item in sorted(items, key=lambda x: tuple(str(v) for v in x)):
        h.update(("\0".join(str(v) for v in item) + "\n").encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def parse_conf_simple(path):
    """Minimal conf reader for app.conf: {stanza: {key: value}}; missing file -> {}."""
    result = {}
    try:
        text = read_bytes(path, MAX_COPY_BYTES).decode("utf-8", "replace")
    except Exception:
        return result
    stanza = "default"
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            stanza = line[1:-1].strip()
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            result.setdefault(stanza, {})[key.strip()] = value.strip()
    return result


def manifest_version(path):
    try:
        data = json.loads(read_bytes(path, MAX_COPY_BYTES).decode("utf-8", "replace"))
        return data["info"]["id"]["version"]
    except Exception:
        return None


def read_text_or_none(path):
    try:
        return read_bytes(path, MAX_COPY_BYTES).decode("utf-8", "replace").strip()
    except Exception:
        return None


# --- collection ---------------------------------------------------------------------

class Collector(object):
    def __init__(self, splunk_home, salt, btool, max_seconds, out, local_only_patterns=()):
        self.home = os.path.abspath(splunk_home)
        self.etc = os.path.join(self.home, "etc")
        self.redactor = Redactor(salt)
        self.btool = btool
        self.local_only_patterns = list(DEFAULT_LOCAL_ONLY_APPS) + list(local_only_patterns)
        self.local_only_apps = {}
        self.apps = []
        self.local_only_default_dirs = []
        self.deadline = time.time() + max_seconds
        self.tar = tarfile.open(fileobj=out, mode="w|gz")
        self.total = 0
        self.files = []
        self.path_checks = []
        self.errors = []
        self.btool_results = {}
        self.system_files = {}

    def add(self, name, data):
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mtime = int(time.time())
        info.mode = 0o644
        self.tar.addfile(info, io.BytesIO(data))
        self.total += len(data)

    def over_budget(self):
        if time.time() > self.deadline:
            return "time budget exceeded"
        if self.total > MAX_TOTAL_BYTES:
            return "size budget exceeded"
        return None

    def is_local_only(self, app):
        for pattern in self.local_only_patterns:
            if fnmatch.fnmatchcase(app, pattern):
                return pattern
        return None

    def walk_root(self, root, active):
        base = os.path.join(self.etc, root)
        if not os.path.isdir(base):
            return
        if root not in APP_ROOTS:
            self.walk_tree(base, root, active)
            return
        for app in sorted(os.listdir(base)):
            app_dir = os.path.join(base, app)
            if not os.path.isdir(app_dir) or os.path.islink(app_dir):
                self.walk_tree(app_dir, root, active)  # stray file (e.g. a .tgz) in an app root
                continue
            start = len(self.files)
            pattern = self.is_local_only(app)
            if pattern:
                shape = self.walk_local_only(app_dir, root, active, pattern)
            else:
                self.walk_tree(app_dir, root, active)
                shape = None
            self.apps.append(self.app_info(app_dir, root, active, pattern, self.files[start:], shape))

    def app_info(self, app_dir, root, active, pattern, entries, shape):
        """Version and content fingerprints used to compare an app across servers and sites."""
        rel_app = os.path.relpath(app_dir, self.home)
        prefix = rel_app + os.sep
        local, content = [], []
        for e in entries:
            inner = e["path"][len(prefix):]
            if is_local_part(inner):
                local.append((inner, e["sha256"]))
            elif shape is None:
                content.append((inner, e["sha256"], e["size"]))
        if shape is None:
            shape = [(inner, size) for inner, _sha, size in content]
        default_conf = parse_conf_simple(os.path.join(app_dir, "default", "app.conf"))
        local_conf = parse_conf_simple(os.path.join(app_dir, "local", "app.conf"))

        def get(stanza, key):
            for conf in (local_conf, default_conf):  # local wins, as in Splunk
                if key in conf.get(stanza, {}):
                    return conf[stanza][key]
            return None

        return {
            "name": os.path.basename(app_dir), "root": root, "active": active,
            "path": rel_app, "local_only": pattern,
            "version": get("launcher", "version") or get("id", "version"),
            "version_default": default_conf.get("launcher", {}).get("version"),
            "version_local": local_conf.get("launcher", {}).get("version"),
            "manifest_version": manifest_version(os.path.join(app_dir, "app.manifest")),
            "build": get("install", "build"),
            "label": get("ui", "label"),
            "author": get("launcher", "author"),
            "package_id": get("package", "id") or get("id", "name"),
            "state": get("install", "state"),
            "is_configured": get("install", "is_configured"),
            "content_sha": fingerprint(content) if pattern is None else None,
            "content_shape": fingerprint([(i, s) for i, s in shape if not is_local_part(i)]),
            "local_sha": fingerprint(local) if local else None,
            "local_files": len(local),
        }

    def walk_local_only(self, app_dir, root, active, pattern):
        files = size = 0
        shape = []
        for dirpath, _dirnames, filenames in os.walk(app_dir, followlinks=False):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                files += 1
                try:
                    fsize = os.lstat(full).st_size
                except OSError:
                    fsize = -1
                size += max(fsize, 0)
                shape.append((os.path.relpath(full, app_dir), fsize))
        rel_app = os.path.relpath(app_dir, self.home)
        self.local_only_apps[rel_app] = {"pattern": pattern, "files": files, "bytes": size}
        self.local_only_default_dirs.append(os.path.join(app_dir, "default") + os.sep)
        app_conf = os.path.join(app_dir, "default", "app.conf")
        if os.path.isfile(app_conf):
            self.walk_tree(app_conf, root, active)
        for sub in LOCAL_ONLY_SUBDIRS:
            path = os.path.join(app_dir, sub)
            if os.path.isdir(path):
                self.walk_tree(path, root, active)
        return shape

    def walk_tree(self, path, root, active):
        if os.path.isfile(path) or os.path.islink(path):
            self.visit(path, root, active)
            return
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames.sort()
            for fname in sorted(filenames):
                self.visit(os.path.join(dirpath, fname), root, active)

    def visit(self, full, root, active):
        reason = self.over_budget()
        if reason:
            raise BudgetExceeded(reason)
        rel = os.path.relpath(full, self.home)
        try:
            self.index_file(full, rel, root, active)
        except Exception as exc:  # unreadable file etc.
            self.errors.append({"path": rel, "error": repr(exc)})

    def index_file(self, full, rel, root, active):
        st = os.lstat(full)
        entry = {
            "path": rel, "root": root, "active": active, "kind": classify(rel),
            "size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode)),
            "owner": owner_name(st.st_uid), "mtime": int(st.st_mtime),
            "symlink": stat.S_ISLNK(st.st_mode), "sha256": None, "copied": False,
        }
        self.files.append(entry)
        if entry["symlink"] or not stat.S_ISREG(st.st_mode):
            return
        if st.st_size <= MAX_HASH_BYTES:
            entry["sha256"] = sha256_file(full)
        if entry["kind"] == "conf":
            if st.st_size > MAX_COPY_BYTES:
                self.errors.append({"path": rel, "error": "conf too large, not copied"})
                return
            text = read_bytes(full, MAX_COPY_BYTES).decode("utf-8", "replace")
            if active and os.path.basename(full) == "inputs.conf":
                self.path_checks.extend(input_path_checks(text, full, rel, self.home))
            self.add(rel, self.redactor.conf_text(text).encode("utf-8"))
            entry["copied"] = True
        elif entry["kind"] == "script":
            entry["suspected_secrets"] = scan_script_secrets(full)

    def run_btool(self):
        for conf in BTOOL_CONFS:
            reason = self.over_budget()
            if reason:
                self.errors.append({"path": "btool", "error": reason})
                return
            try:
                code, out, err = _run_btool(self.home, conf)
            except Exception as exc:
                self.btool_results[conf] = {"ok": False, "error": repr(exc)}
                continue
            self.btool_results[conf] = {"ok": code == 0, "returncode": code, "stderr": err[-2000:]}
            out, dropped = drop_stock_btool_lines(out, self.local_only_default_dirs)
            self.btool_results[conf]["dropped_local_only_default_lines"] = dropped
            if out:
                self.add("btool/%s.txt" % conf, self.redactor.btool_text(out).encode("utf-8"))

    def collect_system_files(self):
        for src, dest in SYSTEM_FILES:
            if not os.path.exists(src):
                self.system_files[src] = "absent"
                continue
            try:
                text = read_bytes(src, MAX_COPY_BYTES).decode("utf-8", "replace")
            except Exception as exc:
                self.system_files[src] = "unreadable: %r" % exc
                continue
            self.add(dest, self.redactor.system_text(text).encode("utf-8"))
            self.system_files[src] = "copied"

    def manifest(self, started):
        secret_path = os.path.join(self.etc, "auth", "splunk.secret")
        try:
            secret_sha = sha256_file(secret_path)
        except Exception as exc:
            secret_sha = None
            self.errors.append({"path": "etc/auth/splunk.secret", "error": repr(exc)})
        return {
            "schema_version": SCHEMA_VERSION,
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "user": owner_name(os.geteuid()),
            "splunk_home": self.home,
            "splunk_version": read_text_or_none(os.path.join(self.etc, "splunk.version")),
            "instance_cfg": read_text_or_none(os.path.join(self.etc, "instance.cfg")),
            "python": sys.version.split()[0],
            "started_at": started,
            "finished_at": int(time.time()),
            "splunk_secret_sha256": secret_sha,
            "redactions": self.redactor.count,
            "btool": self.btool_results,
            "system_files": self.system_files,
            "apps": self.apps,
            "local_only_apps": self.local_only_apps,
            "local_only_patterns": self.local_only_patterns,
            "path_checks": self.path_checks,
            "files": self.files,
            "errors": self.errors,
        }

    def run(self):
        started = int(time.time())
        try:
            for root, active in SCAN_ROOTS:
                self.walk_root(root, active)
        except BudgetExceeded as exc:
            self.errors.append({"path": "etc", "error": str(exc)})
        if self.btool:
            self.run_btool()
        self.collect_system_files()
        manifest = self.manifest(started)
        self.add("manifest.json", json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8"))
        self.tar.close()
        log("done: %d files indexed, %d bytes archived, %d redactions, %d errors"
            % (len(self.files), self.total, self.redactor.count, len(self.errors)))


def check(splunk_home):
    etc = os.path.join(splunk_home, "etc")
    report = {
        "hostname": socket.gethostname(),
        "user": owner_name(os.geteuid()),
        "python": sys.version.split()[0],
        "splunk_home": splunk_home,
        "splunk_version": read_text_or_none(os.path.join(etc, "splunk.version")),
        "btool_present": os.access(os.path.join(splunk_home, "bin", "splunk"), os.X_OK),
        "roots": {},
        "system_files": {},
    }
    for root, _active in SCAN_ROOTS:
        path = os.path.join(etc, root)
        report["roots"][root] = (
            "readable" if os.access(path, os.R_OK | os.X_OK)
            else ("absent" if not os.path.exists(path) else "unreadable")
        )
    for src, _dest in SYSTEM_FILES:
        report["system_files"][src] = (
            "readable" if os.access(src, os.R_OK)
            else ("absent" if not os.path.exists(src) else "unreadable")
        )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="splunk-helper read-only remote collector")
    parser.add_argument("--splunk-home", default=os.environ.get("SPLUNK_HOME", "/data/splunk"))
    parser.add_argument("--no-btool", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument("--local-only-app", action="append", default=[],
                        help="extra app name pattern to collect local/ only (repeatable)")
    args = parser.parse_args(argv)

    try:
        os.nice(19)
    except Exception:
        pass

    if args.check:
        sys.stdout.write(json.dumps(check(args.splunk_home), sort_keys=True) + "\n")
        return 0

    salt = globals().get("_INJECTED_SALT", "")
    collector = Collector(args.splunk_home, salt, not args.no_btool, args.max_seconds,
                          sys.stdout.buffer, args.local_only_app)
    collector.run()
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
