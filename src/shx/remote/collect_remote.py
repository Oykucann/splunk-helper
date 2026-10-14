"""splunk-helper remote collector.

Streamed to a target over SSH and executed as one of:

    splunk cmd python3 -B - --splunk-home /data/splunk --summary
    splunk cmd python3 -B - --splunk-home /data/splunk --detail --app apps/TA-x --app deployment-apps/TA-y
    python3 -B - --splunk-home /opt/splunkforwarder --check

READ-ONLY BY CONSTRUCTION (ADR-0001). Reads files, stats paths and runs
`splunk btool <conf> list --debug`; prints one JSON document to stdout and exits.
It never copies files off the host: --summary sends versions and fingerprints only,
--detail sends the (redacted) conf values of the apps asked for. Nothing is written on the
host. tests/test_remote_guard.py enforces this; keep the code boring.

Python 3.6+ (Splunk's bundled interpreter or the OS python3 on forwarders), stdlib only.
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time

SCHEMA_VERSION = 3

APP_ROOTS = ["apps", "peer-apps", "slave-apps", "deployment-apps", "manager-apps",
             "master-apps", "shcluster/apps"]

# Instance-level confs read through btool (small; never props/savedsearches).
SYSTEM_CONFS = ["server", "web", "outputs", "deploymentclient", "distsearch", "limits",
                "authentication", "authorize", "health", "alert_actions", "serverclass"]

# Large vendor apps: only local/ is compared. Splunk's own apps are found from the install
# manifest (builtin_apps); FALLBACK_BUILTIN is used only when no manifest exists.
VENDOR_APPS = [
    "SplunkEnterpriseSecuritySuite", "DA-ESS-*", "SA-AccessProtection", "SA-AuditAndDataProtection",
    "SA-EndpointProtection", "SA-IdentityManagement", "SA-NetworkProtection", "SA-ThreatIntelligence",
    "SA-UEBA", "SA-Utils", "SA-TestModeControl", "SA-ContentVersioning", "SA-Detections",
    "Splunk_SA_CIM", "Splunk_ML_Toolkit", "Splunk_SA_Scientific_Python_*", "missioncontrol",
    "Splunk_TA_ueba",
]
FALLBACK_BUILTIN = [
    "search", "launcher", "learned", "legacy", "sample_app", "user-prefs", "appsbrowser",
    "introspection_generator_addon", "splunk_archiver", "splunk_instrumentation",
    "splunk_monitoring_console", "splunk_secure_gateway", "splunk_rapid_diag",
    "splunk_metrics_workspace", "splunk_httpinput", "splunk_internal_metrics", "splunk_gdi",
    "splunk_assist", "splunk-dashboard-studio", "python_upgrade_readiness_app", "journald_input",
    "alert_logevent", "alert_webhook", "SplunkForwarder", "SplunkLightForwarder",
    "SplunkDeploymentServerConfig", "splunk_ingest_actions", "splunk-visual-exporter",
    "splunk_essentials_*", "splunk_product_guidance", "framework", "gettingstarted",
]
# Top-level app directories left out of the shipped-content fingerprint and file list.
NOT_CONTENT = ("local", "lookups")

MAX_READ_BYTES = 5 * 1024 * 1024
MAX_HASH_BYTES = 50 * 1024 * 1024
BTOOL_TIMEOUT = 60

# --- redaction ----------------------------------------------------------------------

SECRET_KEY_RE = re.compile(
    r"(?i)^(.*pass(word|wd)?|.*secret.*|token|.*_token|.*authtoken|pass4symmkey"
    r"|.*api_?key|.*private_?key|.*access_?key|.*credentials?)$"
)
# Search-time / index-time class names may contain "password" but hold regexes, not secrets.
NOT_SECRET_KEY_RE = re.compile(r"(?i)^(extract|report|transforms|fieldalias|eval|lookup|sedcmd)-")
ENCRYPTED_RE = re.compile(r"\$\d\$[A-Za-z0-9+/=]{8,}")
CONF_KV_RE = re.compile(r"^(\s*#?\s*)([^=\[\s][^=]*?)(\s*=\s*)(.*?)(\s*)$")


class Redactor(object):
    def __init__(self, salt):
        self.salt = salt.encode("utf-8") if salt else b""
        self.count = 0

    def mask(self, value):
        """<redacted:enc:fp> for Splunk-encrypted values, <redacted:plain:fp> for cleartext.
        Equal secrets get equal fingerprints within one run; values never leave the host."""
        self.count += 1
        kind = "enc" if ENCRYPTED_RE.match(value.strip()) else "plain"
        if not self.salt:
            return "<redacted:%s>" % kind
        digest = hmac.new(self.salt, value.encode("utf-8", "replace"), hashlib.sha256)
        return "<redacted:%s:%s>" % (kind, digest.hexdigest()[:12])

    def conf_line(self, line, in_secret_continuation=False):
        """Redact one conf line. Returns (line, value_continues_as_secret)."""
        nl = "\n" if line.endswith("\n") else ""
        if in_secret_continuation:
            body = line.rstrip("\n")
            return self.mask(body) + nl, body.endswith("\\")
        m = CONF_KV_RE.match(line.rstrip("\n"))
        if m:
            prefix, key, sep, value, trail = m.groups()
            if value and SECRET_KEY_RE.match(key) and not NOT_SECRET_KEY_RE.match(key):
                return prefix + key + sep + self.mask(value) + trail + nl, value.endswith("\\")
        return ENCRYPTED_RE.sub(lambda x: self.mask(x.group(0)), line), False

    def conf_text(self, text):
        out, cont = [], False
        for line in text.splitlines(True):
            red, cont = self.conf_line(line, cont)
            out.append(red)
        return "".join(out)

    def btool_text(self, text):
        # btool --debug lines: "<source path><spaces><conf line>"
        out, cont = [], False
        for line in text.splitlines(True):
            m = re.match(r"^(/\S+\s+|[A-Za-z]:\\\S+\s+)(.*)$", line, re.S)
            if m:
                red, cont = self.conf_line(m.group(2), cont)
                out.append(m.group(1) + red)
            else:
                red, cont = self.conf_line(line, cont)
                out.append(red)
        return "".join(out)


# --- helpers ------------------------------------------------------------------------

def read_bytes(path, limit):
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def read_text_or_none(path):
    try:
        return read_bytes(path, MAX_READ_BYTES).decode("utf-8", "replace").strip()
    except Exception:
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fingerprint(items):
    h = hashlib.sha256()
    for item in sorted(items):
        h.update(("\0".join(str(v) for v in item) + "\n").encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def owner_name(uid):
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def parse_kv_file(text):
    out = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_conf(text):
    """[(stanza, key, value, line)] with continuation lines joined."""
    entries, stanza, pending = [], "default", None
    for no, raw in enumerate(text.splitlines(), 1):
        if pending is not None:
            key, parts, start = pending
            parts.append(raw.strip())
            if not raw.rstrip().endswith("\\"):
                entries.append((stanza, key, "\n".join(parts), start))
                pending = None
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            stanza = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        if value.endswith("\\"):
            pending = (key, [value], no)
        else:
            entries.append((stanza, key, value, no))
    if pending is not None:
        entries.append((stanza, pending[0], "\n".join(pending[1]), pending[2]))
    return entries


def stanza_map(text):
    out = {}
    for stanza, key, value, _no in parse_conf(text or ""):
        out.setdefault(stanza, {})[key] = value
    return out


def matches(name, patterns):
    for p in patterns:
        if fnmatch.fnmatchcase(name, p):
            return True
    return False


def _run_btool(splunk_home, conf):
    """The only subprocess call allowed in this file (see tests/test_remote_guard.py)."""
    exe = os.path.join(splunk_home, "bin", "splunk")
    proc = subprocess.run(
        [exe, "btool", conf, "list", "--debug"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=BTOOL_TIMEOUT,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


# --- Splunk's own apps (install manifest) -------------------------------------------

_MANIFEST_APP_RE = re.compile(r"(?:^|/)etc/apps/([^/\s]+)")


def builtin_apps(splunk_home):
    """(manifest file, app names shipped with this installation) from the newest *-manifest."""
    try:
        names = [n for n in os.listdir(splunk_home) if n.endswith("-manifest")]
    except OSError:
        names = []
    if not names:
        return None, []
    newest = max(names, key=lambda n: os.stat(os.path.join(splunk_home, n)).st_mtime)
    apps = set()
    try:
        with open(os.path.join(splunk_home, newest), "rb") as fh:
            for raw in fh:
                m = _MANIFEST_APP_RE.search(raw.decode("utf-8", "replace"))
                if m:
                    apps.add(m.group(1))
    except OSError:
        return None, []
    return newest, sorted(apps)


class AppClassifier(object):
    def __init__(self, splunk_home, extra_vendor):
        self.manifest, builtins = builtin_apps(splunk_home)
        self.builtins = set(builtins)
        self.vendor = VENDOR_APPS + list(extra_vendor)

    def kind(self, name):
        if self.manifest and name in self.builtins:
            return "builtin"
        if not self.manifest and matches(name, FALLBACK_BUILTIN):
            return "builtin"
        if matches(name, self.vendor):
            return "vendor"
        return "custom"


# --- Splunk service and installs (file reads only) ----------------------------------

INSTALL_CANDIDATES = ["/opt/splunk", "/opt/splunkforwarder", "/data/splunk", "/data/splunkforwarder"]
UNIT_DIRS = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]
UNIT_KEYS = ("ExecStart", "User", "Group", "Restart", "LimitNOFILE", "LimitNPROC", "LimitCORE",
             "LimitFSIZE", "LimitDATA", "LimitAS", "MemoryLimit", "MemoryMax", "MemoryHigh",
             "CPUQuota", "CPUShares", "CPUWeight", "TasksMax", "Delegate", "KillMode",
             "TimeoutStopSec", "Nice")
PROC_LIMITS = ("Max open files", "Max processes", "Max file size", "Max core file size",
               "Max data size", "Max address space")
PRODUCTS = {"splunk": "Splunk Enterprise", "universalforwarder": "Universal Forwarder"}


def install_info(home):
    version = parse_kv_file(read_text_or_none(os.path.join(home, "etc", "splunk.version")))
    if not version:
        return None
    info = {"home": home, "product": PRODUCTS.get(version.get("PRODUCT", ""), version.get("PRODUCT")),
            "version": version.get("VERSION"), "build": version.get("BUILD"), "running": False}
    pid_text = read_text_or_none(os.path.join(home, "var", "run", "splunk", "splunkd.pid"))
    pid = pid_text.split()[0] if pid_text else ""
    if pid.isdigit() and os.path.isdir("/proc/" + pid):
        info["running"] = True
        info["pid"] = int(pid)
        try:
            info["run_user"] = owner_name(os.stat("/proc/" + pid).st_uid)
        except OSError:
            pass
        info["process_limits"] = parse_limits(read_text_or_none("/proc/%s/limits" % pid))
    return info


def unit_settings(texts):
    settings = {}
    for text in texts:
        for line in (text or "").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith(("#", ";")):
                k, v = line.split("=", 1)
                if k.strip() in UNIT_KEYS:
                    settings[k.strip()] = v.strip()
    return settings


def splunk_units():
    units, seen = [], set()
    for d in UNIT_DIRS:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".service") or "splunk" not in name.lower() or name in seen:
                continue
            seen.add(name)  # first directory wins, as in systemd (/etc overrides /usr/lib)
            path = os.path.join(d, name)
            texts, dropins = [read_text_or_none(path)], []
            for dd in [os.path.join(x, name + ".d") for x in UNIT_DIRS]:
                try:
                    for f in sorted(os.listdir(dd)):
                        if f.endswith(".conf"):
                            dropins.append(os.path.join(dd, f))
                            texts.append(read_text_or_none(os.path.join(dd, f)))
                except OSError:
                    pass
            enabled = any(os.path.exists(os.path.join(UNIT_DIRS[0], t + ".wants", name))
                          for t in ("multi-user.target", "default.target"))
            units.append({"unit": name, "path": path, "dropins": dropins, "enabled": enabled,
                          "settings": unit_settings(texts)})
    return units


def parse_limits(text):
    limits = {}
    for line in (text or "").splitlines():
        for name in PROC_LIMITS:
            if line.startswith(name):
                parts = line[len(name):].split()
                if len(parts) >= 2:
                    limits[name] = {"soft": parts[0], "hard": parts[1]}
    return limits


# --- operating system (file reads only) ---------------------------------------------

THP_DIRS = ["/sys/kernel/mm/transparent_hugepage", "/sys/kernel/mm/redhat_transparent_hugepage"]
NTP_FILES = ["/etc/chrony.conf", "/etc/chrony/chrony.conf", "/etc/ntp.conf",
             "/etc/systemd/timesyncd.conf"]
RESOLV_FILES = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"]
SELINUX_ENFORCE = "/sys/fs/selinux/enforce"
SELINUX_CONFIG = "/etc/selinux/config"
OS_RELEASE = "/etc/os-release"


def _bracketed(text):
    """'always madvise [never]' -> 'never'."""
    m = re.search(r"\[([^\]]+)\]", text or "")
    return m.group(1) if m else (text or None)


def ntp_servers():
    out = []
    for path in NTP_FILES:
        for line in (read_text_or_none(path) or "").splitlines():
            line = line.split("#", 1)[0].strip()
            words = line.split()
            if words and words[0] in ("server", "pool", "peer"):
                out.append({"file": path, "type": words[0], "server": words[1] if len(words) > 1 else ""})
            elif line.startswith(("NTP=", "FallbackNTP=")):
                for srv in line.split("=", 1)[1].split():
                    out.append({"file": path, "type": line.split("=", 1)[0], "server": srv})
    return out


def dns_info():
    out = {}
    for path in RESOLV_FILES:
        text = read_text_or_none(path)
        if text is None:
            continue
        servers, search = [], []
        for line in text.splitlines():
            words = line.split("#", 1)[0].split()
            if len(words) > 1 and words[0] == "nameserver":
                servers.append(words[1])
            elif words and words[0] in ("search", "domain"):
                search += words[1:]
        out[path] = {"nameservers": servers, "search": search}
    return out


def meminfo_mb():
    for line in (read_text_or_none("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            try:
                return int(line.split()[1]) // 1024
            except (IndexError, ValueError):
                return None
    return None


def os_info():
    release = parse_kv_file(read_text_or_none(OS_RELEASE))
    enforce = read_text_or_none(SELINUX_ENFORCE)
    selinux_config = parse_kv_file(read_text_or_none(SELINUX_CONFIG))
    thp = {}
    for d in THP_DIRS:
        if os.path.isdir(d):
            thp = {"enabled": _bracketed(read_text_or_none(os.path.join(d, "enabled"))),
                   "defrag": _bracketed(read_text_or_none(os.path.join(d, "defrag"))), "path": d}
            break
    return {
        "os": release.get("PRETTY_NAME", "").strip('"') or None,
        "kernel": read_text_or_none("/proc/sys/kernel/osrelease"),
        "cpus": os.cpu_count(), "memory_mb": meminfo_mb(),
        "selinux": {"current": {"1": "enforcing", "0": "permissive"}.get(enforce or "", "disabled"),
                    "config": selinux_config.get("SELINUX")},
        "thp": thp,
        "session_limits": parse_limits(read_text_or_none("/proc/self/limits")),
        "ntp": ntp_servers(), "dns": dns_info(),
    }


def service_info(splunk_home):
    homes = [splunk_home] + [h for h in INSTALL_CANDIDATES if h != splunk_home]
    installs = [i for i in (install_info(h) for h in homes) if i]
    return {"installs": installs, "systemd_units": splunk_units(),
            "initd_script": os.path.exists("/etc/init.d/splunk")}


# --- apps ---------------------------------------------------------------------------

def app_dirs(splunk_home):
    etc = os.path.join(splunk_home, "etc")
    for root in APP_ROOTS:
        try:
            names = sorted(os.listdir(os.path.join(etc, root)))
        except OSError:
            continue
        for name in names:
            path = os.path.join(etc, root, name)
            if os.path.isdir(path) and not os.path.islink(path):
                yield root, name, path


def is_local_part(rel):
    return rel.split(os.sep, 1)[0] == "local" or rel == os.path.join("metadata", "local.meta")


def app_summary(root, name, app_dir, kind):
    default = stanza_map(read_text_or_none(os.path.join(app_dir, "default", "app.conf")))
    local = stanza_map(read_text_or_none(os.path.join(app_dir, "local", "app.conf")))

    def get(stanza, key):
        for conf in (local, default):  # local wins, as in Splunk
            if key in conf.get(stanza, {}):
                return conf[stanza][key]
        return None

    manifest_version = None
    try:
        manifest_version = json.loads(read_text_or_none(os.path.join(app_dir, "app.manifest")) or "")["info"]["id"]["version"]
    except Exception:
        pass
    content, local_items, lookups = [], [], 0
    for dirpath, dirnames, filenames in os.walk(app_dir, followlinks=False):
        dirnames.sort()
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, app_dir)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            regular = stat.S_ISREG(st.st_mode)
            if is_local_part(rel):
                local_items.append((rel, sha256_file(full) if regular else "link"))
            elif rel.split(os.sep, 1)[0] == "lookups":
                lookups += 1
            elif kind == "custom" and regular and st.st_size <= MAX_HASH_BYTES:
                content.append((rel, sha256_file(full)))
            else:
                content.append((rel, st.st_size))  # built-in / vendor: path + size only
    return {
        "root": root, "name": name, "kind": kind,
        "version": get("launcher", "version") or get("id", "version") or manifest_version,
        "build": get("install", "build"), "label": get("ui", "label"),
        "disabled": (get("install", "state") or "").lower() == "disabled",
        "content_fp": fingerprint(content), "local_fp": fingerprint(local_items) if local_items else None,
        "local_files": len(local_items), "lookup_files": lookups,
    }


def app_detail(splunk_home, root, name, kind, redactor):
    """Redacted conf values (and non-conf file hashes for custom apps) of one app."""
    app_dir = os.path.join(splunk_home, "etc", root, name)
    if not os.path.isdir(app_dir):
        return {"root": root, "name": name, "missing": True}
    layers = ("default", "local") if kind == "custom" else ("local",)
    settings = []
    for layer in layers:
        layer_dir = os.path.join(app_dir, layer)
        try:
            confs = sorted(f for f in os.listdir(layer_dir) if f.endswith(".conf"))
        except OSError:
            confs = []
        for f in confs:
            text = redactor.conf_text(read_text_or_none(os.path.join(layer_dir, f)) or "")
            for stanza, key, value, _no in parse_conf(text):
                settings.append([layer, f[:-len(".conf")], stanza, key, value])
        meta = read_text_or_none(os.path.join(app_dir, "metadata", layer + ".meta"))
        for stanza, key, value, _no in parse_conf(meta or ""):
            settings.append([layer, "metadata", stanza, key, value])
    files = []
    if kind == "custom":
        for dirpath, dirnames, filenames in os.walk(app_dir, followlinks=False):
            dirnames.sort()
            for fname in sorted(filenames):
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, app_dir)
                if rel.split(os.sep, 1)[0] in NOT_CONTENT + ("default", "metadata"):
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_size <= MAX_HASH_BYTES:
                    files.append([rel, sha256_file(full)[:16]])
    return {"root": root, "name": name, "kind": kind, "settings": settings, "files": files}


# --- modes --------------------------------------------------------------------------

def summary(splunk_home, salt, extra_vendor, btool):
    started = time.time()
    redactor = Redactor(salt)
    classifier = AppClassifier(splunk_home, extra_vendor)
    errors, apps = [], []
    for root, name, path in app_dirs(splunk_home):
        try:
            apps.append(app_summary(root, name, path, classifier.kind(name)))
        except Exception as exc:
            errors.append({"path": "%s/%s" % (root, name), "error": repr(exc)})
    btool_out = {}
    if btool and os.access(os.path.join(splunk_home, "bin", "splunk"), os.X_OK):
        for conf in SYSTEM_CONFS:
            try:
                code, out, err = _run_btool(splunk_home, conf)
            except Exception as exc:
                errors.append({"path": "btool " + conf, "error": repr(exc)})
                continue
            if code != 0:
                errors.append({"path": "btool " + conf, "error": err[-500:]})
            btool_out[conf] = redactor.btool_text(out)
    secret = os.path.join(splunk_home, "etc", "auth", "splunk.secret")
    return {
        "schema_version": SCHEMA_VERSION, "mode": "summary",
        "hostname": socket.gethostname(), "fqdn": socket.getfqdn(), "user": owner_name(os.geteuid()),
        "python": sys.version.split()[0], "splunk_home": splunk_home,
        "splunk_version": read_text_or_none(os.path.join(splunk_home, "etc", "splunk.version")),
        "splunk_secret_fp": sha256_file(secret)[:16] if os.path.isfile(secret) else None,
        "builtin_source": classifier.manifest or "fallback list",
        "service": service_info(splunk_home), "os": os_info(), "apps": apps, "btool": btool_out,
        "redactions": redactor.count, "errors": errors, "seconds": round(time.time() - started, 1),
    }


def detail(splunk_home, salt, wanted, extra_vendor):
    redactor = Redactor(salt)
    classifier = AppClassifier(splunk_home, extra_vendor)
    apps = []
    for item in wanted:
        root, _sep, name = item.rpartition("/")
        if root not in APP_ROOTS or not name or name in (".", ".."):
            apps.append({"root": root, "name": name, "error": "invalid app reference"})
            continue
        apps.append(app_detail(splunk_home, root, name, classifier.kind(name), redactor))
    return {"schema_version": SCHEMA_VERSION, "mode": "detail", "hostname": socket.gethostname(),
            "apps": apps, "redactions": redactor.count}


def check(splunk_home):
    return {
        "hostname": socket.gethostname(), "user": owner_name(os.geteuid()),
        "python": sys.version.split()[0], "splunk_home": splunk_home,
        "splunk_version": read_text_or_none(os.path.join(splunk_home, "etc", "splunk.version")),
        "btool_present": os.access(os.path.join(splunk_home, "bin", "splunk"), os.X_OK),
        "apps_readable": os.access(os.path.join(splunk_home, "etc", "apps"), os.R_OK | os.X_OK),
        "service": service_info(splunk_home), "os": os_info(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="splunk-helper read-only remote collector")
    parser.add_argument("--splunk-home", default=os.environ.get("SPLUNK_HOME", "/data/splunk"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--summary", action="store_true")
    mode.add_argument("--detail", action="store_true")
    parser.add_argument("--app", action="append", default=[], help="root/name for --detail")
    parser.add_argument("--no-btool", action="store_true")
    parser.add_argument("--vendor-app", action="append", default=[],
                        help="extra app name pattern compared by local/ only")
    args = parser.parse_args(argv)
    try:
        os.nice(19)
    except Exception:
        pass
    home = os.path.abspath(args.splunk_home)
    salt = globals().get("_INJECTED_SALT", "")
    if args.check:
        result = check(home)
    elif args.detail:
        result = detail(home, salt, args.app, args.vendor_app)
    else:
        result = summary(home, salt, args.vendor_app, not args.no_btool)
    sys.stdout.write(json.dumps(result, sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
