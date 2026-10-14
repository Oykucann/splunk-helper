"""Run the remote collector against a fake $SPLUNK_HOME exactly as the driver streams it."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shx.collect.cli import REMOTE_SCRIPT, script_payload
from shx.remote.collect_remote import Redactor

ENC = "$7$abcdefghijklmnopqrstuvwxyz0123456789=="


def write(path: Path, text: str, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


@pytest.fixture
def splunk_home(tmp_path):
    home = tmp_path / "splunk"
    etc = home / "etc"
    write(etc / "splunk.version", "VERSION=9.1.2\nBUILD=b6436b649711\nPRODUCT=splunk\n")
    write(etc / "auth" / "splunk.secret", "supersecretvalue\n", 0o400)
    # Install manifest: lists the apps shipped with Splunk.
    write(home / "splunk-9.1.2-b6436b649711-linux-2.6-x86_64-manifest",
          "d 755 splunk splunk splunk/etc/apps/search -\n"
          "f 444 splunk splunk splunk/etc/apps/search/default/app.conf 1a2b\n"
          "f 444 splunk splunk splunk/etc/apps/splunk-dashboard-studio/default/app.conf 3c4d\n")
    # Built-in app with a local change.
    write(etc / "apps" / "search" / "default" / "app.conf", "[launcher]\nversion = 9.1.2\n")
    write(etc / "apps" / "search" / "default" / "savedsearches.conf", "[stock]\nsearch = x\n" * 50)
    write(etc / "apps" / "search" / "local" / "savedsearches.conf", "[mine]\nsearch = index=a\n")
    write(etc / "apps" / "splunk-dashboard-studio" / "default" / "app.conf", "[launcher]\nversion = 1.11\n")
    # Vendor app (ES).
    es = etc / "apps" / "SplunkEnterpriseSecuritySuite"
    write(es / "default" / "app.conf", "[launcher]\nversion = 7.3.1\n")
    write(es / "default" / "savedsearches.conf", "[ES stock]\nsearch = index=*\n" * 2000)
    write(es / "local" / "savedsearches.conf", "[ES stock]\ndisabled = 1\n")
    # Custom app.
    ta = etc / "apps" / "TA-acme"
    write(ta / "default" / "app.conf", "[launcher]\nversion = 1.2.3\n[install]\nstate = disabled\n")
    write(ta / "default" / "props.conf", "[acme]\nTRUNCATE = 10000\nEXTRACT-password = password=(?<pw>\\S+)\n")
    write(ta / "local" / "passwords.conf", f"[credential::svc:]\npassword = {ENC}\n")
    write(ta / "local" / "outputs.conf", "[tcpout]\nsslPassword = hunter22\n")
    write(ta / "bin" / "poll.sh", "#!/bin/sh\necho hi\n", 0o755)
    write(ta / "lookups" / "users.csv", "user,email\nalice,alice@example.com\n")
    write(ta / "metadata" / "local.meta", "[]\naccess = read : [ * ]\n")
    write(etc / "deployment-apps" / "TA-acme" / "default" / "app.conf", "[launcher]\nversion = 1.2.4\n")
    # Fake splunk binary: only answers btool, like the real one would.
    write(home / "bin" / "splunk",
          "#!/bin/sh\n[ \"$1\" = btool ] || exit 9\n"
          "[ \"$2\" = server ] || exit 0\n"
          f"echo '{etc}/system/local/server.conf  [general]'\n"
          f"echo '{etc}/system/local/server.conf  pass4SymmKey = {ENC}'\n"
          f"echo '{etc}/system/local/server.conf  serverName = hf01a'\n", 0o755)
    return home


def tree_state(root: Path):
    return sorted((str(p), p.stat().st_mtime_ns, p.stat().st_mode) for p in root.rglob("*"))


def run_remote(home: Path, *args, salt="s4lt"):
    proc = subprocess.run([sys.executable, "-B", "-", "--splunk-home", str(home), *args],
                          input=script_payload(salt), capture_output=True, check=True)
    return proc.stdout.decode(), json.loads(proc.stdout.decode().strip().splitlines()[-1])


def apps_by_key(summary):
    return {(a["root"], a["name"]): a for a in summary["apps"]}


def test_writes_nothing_on_target(splunk_home):
    before = tree_state(splunk_home.parent)
    run_remote(splunk_home, "--summary")
    run_remote(splunk_home, "--detail", "--app", "apps/TA-acme", "--app", "apps/search")
    run_remote(splunk_home, "--check")
    assert tree_state(splunk_home.parent) == before


def test_summary_sends_fingerprints_not_files(splunk_home):
    raw, s = run_remote(splunk_home, "--summary")
    assert len(raw) < 20000  # ES default (thousands of stanzas) is not in it
    for leaked in ("$7$abcdefgh", "hunter22", "supersecretvalue", "alice@example.com", "TRUNCATE",
                   "ES stock", "s4lt"):
        assert leaked not in raw, leaked
    apps = apps_by_key(s)
    assert apps[("apps", "search")]["kind"] == "builtin"
    assert apps[("apps", "splunk-dashboard-studio")]["kind"] == "builtin"  # from the install manifest
    assert apps[("apps", "SplunkEnterpriseSecuritySuite")]["kind"] == "vendor"
    acme = apps[("apps", "TA-acme")]
    assert (acme["kind"], acme["version"], acme["disabled"]) == ("custom", "1.2.3", True)
    assert acme["local_files"] == 3 and acme["lookup_files"] == 1 and acme["content_fp"]
    assert apps[("deployment-apps", "TA-acme")]["version"] == "1.2.4"
    assert s["builtin_source"].endswith("-manifest")
    assert s["service"]["installs"][0]["product"] == "Splunk Enterprise"
    assert s["splunk_secret_fp"] and "supersecretvalue" not in raw


def test_summary_btool_is_redacted_and_limited_to_system_confs(splunk_home):
    _, s = run_remote(splunk_home, "--summary")
    assert set(s["btool"]) == {"server", "web", "outputs", "deploymentclient", "distsearch", "limits",
                               "authentication", "authorize", "health", "alert_actions", "serverclass"}
    assert "serverName = hf01a" in s["btool"]["server"]
    assert "$7$" not in s["btool"]["server"] and "<redacted:enc:" in s["btool"]["server"]


def test_local_change_moves_local_fingerprint_only(splunk_home):
    _, before = run_remote(splunk_home, "--summary")
    write(splunk_home / "etc" / "apps" / "TA-acme" / "local" / "props.conf", "[acme]\nX = 1\n")
    _, after = run_remote(splunk_home, "--summary")
    b, a = apps_by_key(before)[("apps", "TA-acme")], apps_by_key(after)[("apps", "TA-acme")]
    assert b["content_fp"] == a["content_fp"] and b["local_fp"] != a["local_fp"]


def test_detail_values_redacted_and_vendor_local_only(splunk_home):
    raw, d = run_remote(splunk_home, "--detail", "--app", "apps/TA-acme",
                        "--app", "apps/SplunkEnterpriseSecuritySuite", "--app", "../etc", "--app", "apps/nope")
    apps = {a["name"]: a for a in d["apps"]}
    acme = {(l, c, st, k): v for l, c, st, k, v in apps["TA-acme"]["settings"]}
    assert acme[("default", "props", "acme", "TRUNCATE")] == "10000"
    assert acme[("default", "props", "acme", "EXTRACT-password")] == "password=(?<pw>\\S+)"
    assert acme[("local", "passwords", "credential::svc:", "password")].startswith("<redacted:enc:")
    assert acme[("local", "outputs", "tcpout", "sslPassword")].startswith("<redacted:plain:")
    assert acme[("local", "metadata", "", "access")] == "read : [ * ]"
    assert [f[0] for f in apps["TA-acme"]["files"]] == ["bin/poll.sh"]  # no lookups, no content
    es = apps["SplunkEnterpriseSecuritySuite"]["settings"]
    assert es == [["local", "savedsearches", "ES stock", "disabled", "1"]]
    assert apps["etc"]["error"] == "invalid app reference" and apps["nope"]["missing"]
    for leaked in ("hunter22", "$7$abcdefgh", "alice@example.com", "echo hi"):
        assert leaked not in raw


def test_fingerprints_equal_for_equal_secrets(splunk_home):
    _, s = run_remote(splunk_home, "--summary")
    _, d = run_remote(splunk_home, "--detail", "--app", "apps/TA-acme")
    fp_btool = s["btool"]["server"].split("pass4SymmKey = ")[1].split()[0]
    fp_detail = {k: v for _l, _c, _s, k, v in d["apps"][0]["settings"]}["password"]
    assert fp_btool == fp_detail  # same encrypted value, same fingerprint within one salt


def test_check_mode(splunk_home):
    _, c = run_remote(splunk_home, "--check")
    assert c["apps_readable"] and c["btool_present"] and c["service"]["installs"]


def test_redactor_continuation_line():
    out = Redactor("x").conf_text("[x]\npassword = abc\\\ndef\nother = 1\n")
    assert "abc" not in out and "def" not in out and "other = 1" in out


def test_redaction_marks_encrypted_vs_cleartext():
    out = Redactor("x").conf_text(f"[a]\npassword = {ENC}\n[b]\npassword = hunter22\n")
    assert "password = <redacted:enc:" in out and "password = <redacted:plain:" in out


def test_service_detection(tmp_path, monkeypatch):
    import shx.remote.collect_remote as remote
    home = tmp_path / "opt" / "splunkforwarder"
    write(home / "etc" / "splunk.version", "VERSION=9.2.1\nBUILD=abc\nPRODUCT=universalforwarder\n")
    write(home / "var" / "run" / "splunk" / "splunkd.pid", "999999999\n")  # not a live pid
    units = tmp_path / "etc" / "systemd" / "system"
    write(units / "SplunkForwarder.service",
          "[Service]\nExecStart=/opt/splunkforwarder/bin/splunk _internal_launch_under_systemd\n"
          "User=splunkfwd\nLimitNOFILE=65536\nMemoryLimit=2G\n")
    write(units / "SplunkForwarder.service.d" / "override.conf", "[Service]\nLimitNOFILE=100000\n")
    (units / "multi-user.target.wants").mkdir(parents=True)
    (units / "multi-user.target.wants" / "SplunkForwarder.service").write_text("")
    write(units / "sshd.service", "[Service]\nExecStart=/usr/sbin/sshd\n")
    monkeypatch.setattr(remote, "UNIT_DIRS", [str(units)])
    monkeypatch.setattr(remote, "INSTALL_CANDIDATES", [])
    info = remote.service_info(str(home))
    [inst] = info["installs"]
    assert (inst["product"], inst["version"], inst["running"]) == ("Universal Forwarder", "9.2.1", False)
    [unit] = info["systemd_units"]
    assert unit["unit"] == "SplunkForwarder.service" and unit["enabled"] is True
    assert unit["settings"]["LimitNOFILE"] == "100000" and unit["settings"]["MemoryLimit"] == "2G"


def test_builtin_fallback_without_manifest(tmp_path):
    import shx.remote.collect_remote as remote
    c = remote.AppClassifier(str(tmp_path), ["TA-big-*"])
    assert c.manifest is None
    assert c.kind("search") == "builtin" and c.kind("TA-big-x") == "vendor" and c.kind("org_x") == "custom"


def test_remote_script_is_self_contained():
    assert "from shx" not in REMOTE_SCRIPT.read_text()


def test_os_info_from_files(tmp_path, monkeypatch):
    import shx.remote.collect_remote as remote
    write(tmp_path / "selinux" / "enforce", "1\n")
    write(tmp_path / "selinux" / "config", "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
    write(tmp_path / "os-release", 'PRETTY_NAME="Red Hat Enterprise Linux 8.9 (Ootpa)"\n')
    thp = tmp_path / "thp"
    write(thp / "enabled", "always madvise [never]\n")
    write(thp / "defrag", "[always] defer madvise never\n")
    write(tmp_path / "chrony.conf", "# pool 2.rhel.pool.ntp.org iburst\nserver 10.0.0.1 iburst\npool ntp.corp prefer\n")
    write(tmp_path / "timesyncd.conf", "[Time]\nNTP=10.0.0.2 10.0.0.3\n")
    write(tmp_path / "resolv.conf", "search corp.local\nnameserver 10.0.0.53\nnameserver 10.0.0.54\n")
    monkeypatch.setattr(remote, "SELINUX_ENFORCE", str(tmp_path / "selinux" / "enforce"))
    monkeypatch.setattr(remote, "SELINUX_CONFIG", str(tmp_path / "selinux" / "config"))
    monkeypatch.setattr(remote, "OS_RELEASE", str(tmp_path / "os-release"))
    monkeypatch.setattr(remote, "THP_DIRS", [str(thp)])
    monkeypatch.setattr(remote, "NTP_FILES", [str(tmp_path / "chrony.conf"), str(tmp_path / "timesyncd.conf")])
    monkeypatch.setattr(remote, "RESOLV_FILES", [str(tmp_path / "resolv.conf")])

    o = remote.os_info()
    assert o["os"] == "Red Hat Enterprise Linux 8.9 (Ootpa)"
    assert o["selinux"] == {"current": "enforcing", "config": "enforcing"}
    assert (o["thp"]["enabled"], o["thp"]["defrag"]) == ("never", "always")
    assert [n["server"] for n in o["ntp"]] == ["10.0.0.1", "ntp.corp", "10.0.0.2", "10.0.0.3"]
    assert o["dns"][str(tmp_path / "resolv.conf")] == {"nameservers": ["10.0.0.53", "10.0.0.54"],
                                                       "search": ["corp.local"]}
    assert o["cpus"] and isinstance(o["session_limits"], dict)

    monkeypatch.setattr(remote, "SELINUX_ENFORCE", str(tmp_path / "missing"))
    assert remote.os_info()["selinux"]["current"] == "disabled"


def test_summary_contains_os(splunk_home):
    _, s = run_remote(splunk_home, "--summary")
    assert "selinux" in s["os"] and "thp" in s["os"] and "dns" in s["os"]
