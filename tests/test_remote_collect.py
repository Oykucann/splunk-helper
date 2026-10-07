"""Run the remote collector against a fake $SPLUNK_HOME exactly as the driver streams it."""

import io
import json
import os
import subprocess
import sys
import tarfile
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
    write(etc / "splunk.version", "VERSION=9.1.2\n")
    write(etc / "auth" / "splunk.secret", "supersecretvalue\n", 0o400)
    write(etc / "system" / "local" / "server.conf",
          f"[general]\nserverName = hf01a\npass4SymmKey = {ENC}\n\n[sslConfig]\nsslPassword = {ENC}\n")
    ta = etc / "apps" / "TA-acme"
    write(ta / "default" / "app.conf", "[launcher]\nversion = 1.2.3\n")
    write(ta / "default" / "inputs.conf",
          "[monitor:///var/log/acme/*.log]\nsourcetype = acme\n\n"
          "[monitor:///var/log/present]\n\n"
          "[script://./bin/missing.sh]\ninterval = 60\n\n"
          "[script://./bin/poll.sh]\ninterval = 300\n\n"
          "[http://acme_hec]\ntoken = 11111111-2222-3333-4444-555555555555\n")
    write(ta / "default" / "props.conf",
          "[acme]\nEXTRACT-password = password=(?<pw>\\S+)\nTIME_FORMAT = %s\n")
    write(ta / "local" / "passwords.conf", f"[credential::svc:]\npassword = {ENC}\n")
    write(ta / "local" / "outputs.conf", "[tcpout]\n# old: sslPassword = hunter22\n")
    write(ta / "bin" / "poll.sh", "#!/bin/sh\nAPI_KEY=abcd1234efgh\ncurl -u admin:x https://x\n", 0o755)
    write(ta / "lookups" / "users.csv", "user,email\nalice,alice@example.com\n")
    write(ta / "metadata" / "local.meta", "[]\naccess = read : [ * ]\n")
    write(etc / "deployment-apps" / "org_all_outputs" / "local" / "outputs.conf",
          "[tcpout:primary]\nserver = idx1:9997\n")
    write(etc / "deployment-apps" / "org_all_outputs" / "default" / "inputs.conf",
          "[monitor:///does/not/matter]\n")
    (tmp_path / "var" / "log" / "acme").mkdir(parents=True)
    # Enterprise Security: only local/, metadata/, lookups index and default/app.conf.
    es = etc / "apps" / "SplunkEnterpriseSecuritySuite"
    write(es / "default" / "app.conf", "[launcher]\nversion = 7.3.1\n")
    write(es / "default" / "savedsearches.conf", "[ES stock search]\nsearch = index=*\n" * 2000)
    write(es / "local" / "savedsearches.conf", "[ES stock search]\ndisabled = 1\n")
    write(es / "appserver" / "static" / "bundle.js", "x" * 100000)
    write(es / "lookups" / "threat.csv", "ip\n1.2.3.4\n")
    write(etc / "apps" / "SA-ThreatIntelligence" / "default" / "inputs.conf", "[stock]\n")
    write(etc / "shcluster" / "apps" / "DA-ESS-NetworkProtection" / "default" / "macros.conf", "[m]\n")
    write(etc / "apps" / "Splunk_TA_ForIndexers" / "default" / "props.conf", "[ftp]\nTIME_FORMAT = %s\n")
    write(etc / "apps" / "SA-acme" / "default" / "props.conf", "[acme]\nKV_MODE = json\n")
    write(etc / "apps" / "big_vendor_app" / "default" / "props.conf", "[v]\n")
    # SmartStore (S3) credentials on the CM.
    write(etc / "manager-apps" / "org_all_indexes" / "local" / "indexes.conf",
          "[volume:remote_store]\nstorageType = remote\npath = s3://bucket/splunk\n"
          "remote.s3.access_key = AKIAABCDEFGHIJKLMNOP\nremote.s3.secret_key = wJalrXUtnFEMI/K7MDENG\n"
          "remote.s3.endpoint = https://s3.example.com\n")
    # Fake splunk binary: only answers btool, like the real one would.
    write(home / "bin" / "splunk",
          "#!/bin/sh\n[ \"$1\" = btool ] || exit 9\n"
          f"if [ \"$2\" = savedsearches ]; then echo '{etc}/apps/SplunkEnterpriseSecuritySuite/default/savedsearches.conf [ES stock search]'; "
          f"echo '{etc}/apps/SplunkEnterpriseSecuritySuite/default/savedsearches.conf search = index=*'; "
          f"echo '{etc}/apps/SplunkEnterpriseSecuritySuite/local/savedsearches.conf   disabled = 1'; exit 0; fi\n"
          "[ \"$2\" = server ] || exit 0\n"
          f"echo '{etc}/system/local/server.conf  pass4SymmKey = {ENC}'\n"
          f"echo '{etc}/system/local/server.conf  serverName = hf01a'\n", 0o755)
    return home


def tree_state(root: Path):
    return sorted((str(p), p.stat().st_mtime_ns, p.stat().st_mode)
                  for p in root.rglob("*"))


def run_remote(home: Path, *extra, salt="s4lt"):
    proc = subprocess.run(
        [sys.executable, "-", "--splunk-home", str(home), *extra],
        input=script_payload(salt), capture_output=True, check=True,
    )
    return proc


def open_snapshot(stdout: bytes):
    tar = tarfile.open(fileobj=io.BytesIO(stdout), mode="r:gz")
    manifest = json.load(tar.extractfile("manifest.json"))
    return tar, manifest


def text(tar, name):
    return tar.extractfile(name).read().decode()


def test_writes_nothing_on_target(splunk_home):
    before = tree_state(splunk_home.parent)
    run_remote(splunk_home)
    assert tree_state(splunk_home.parent) == before


def test_snapshot_contents_and_redaction(splunk_home):
    tar, manifest = open_snapshot(run_remote(splunk_home).stdout)
    names = set(tar.getnames())

    assert manifest["splunk_version"] == "VERSION=9.1.2"
    assert manifest["splunk_secret_sha256"]
    assert "etc/apps/TA-acme/default/inputs.conf" in names
    assert "etc/deployment-apps/org_all_outputs/local/outputs.conf" in names
    assert "etc/apps/TA-acme/metadata/local.meta" in names
    # Lookups and scripts are indexed but never copied.
    assert "etc/apps/TA-acme/lookups/users.csv" not in names
    assert "etc/apps/TA-acme/bin/poll.sh" not in names
    by_path = {f["path"]: f for f in manifest["files"]}
    assert by_path["etc/apps/TA-acme/lookups/users.csv"]["kind"] == "lookup"
    assert by_path["etc/apps/TA-acme/bin/poll.sh"]["mode"] == "0o755"
    assert by_path["etc/apps/TA-acme/bin/poll.sh"]["suspected_secrets"] == [{"line": 2, "key": "api_key"}]

    blob = b"".join(tar.extractfile(m).read() for m in tar.getmembers() if m.isfile())
    for secret in (b"$7$abcdefgh", b"11111111-2222", b"hunter22", b"supersecretvalue", b"s4lt"):
        assert secret not in blob, secret
    server_conf = text(tar, "etc/system/local/server.conf")
    assert "serverName = hf01a" in server_conf
    assert "pass4SymmKey = <redacted:" in server_conf
    # Regex class names that mention "password" are not secrets.
    assert "EXTRACT-password = password=(?<pw>\\S+)" in text(tar, "etc/apps/TA-acme/default/props.conf")
    assert manifest["redactions"] >= 5


def test_fingerprints_equal_for_equal_secrets(splunk_home):
    tar, _ = open_snapshot(run_remote(splunk_home).stdout)
    server_conf = text(tar, "etc/system/local/server.conf")
    fps = {line.split("= ")[1] for line in server_conf.splitlines() if "<redacted" in line}
    assert len(fps) == 1  # pass4SymmKey and sslPassword share the same encrypted value


def test_path_checks_only_for_active_roots(splunk_home):
    _, manifest = open_snapshot(run_remote(splunk_home).stdout)
    checks = {c["stanza"]: c for c in manifest["path_checks"]}
    assert set(checks) == {
        "monitor:///var/log/acme/*.log", "monitor:///var/log/present",
        "script://./bin/missing.sh", "script://./bin/poll.sh",
    }
    assert checks["script://./bin/poll.sh"]["exists"] is True
    assert checks["script://./bin/missing.sh"]["exists"] is False
    assert checks["monitor:///var/log/acme/*.log"]["wildcard"] is True


def test_btool_output_is_captured_and_redacted(splunk_home):
    tar, manifest = open_snapshot(run_remote(splunk_home).stdout)
    btool = text(tar, "btool/server.txt")
    assert "serverName = hf01a" in btool
    assert "$7$" not in btool and "<redacted:" in btool
    assert manifest["btool"]["server"]["ok"] is True


def test_no_btool_flag(splunk_home):
    tar, manifest = open_snapshot(run_remote(splunk_home, "--no-btool").stdout)
    assert not [n for n in tar.getnames() if n.startswith("btool/")]
    assert manifest["btool"] == {}


def test_check_mode_prints_json_only(splunk_home):
    out = run_remote(splunk_home, "--check").stdout.decode()
    report = json.loads(out)
    assert report["roots"]["apps"] == "readable"
    assert report["roots"]["master-apps"] == "absent"


def test_redactor_system_files():
    r = Redactor("x")
    out = r.system_text("vrrp_instance VI_1 {\n  authentication {\n    auth_pass s3cr3t\n  }\n}\n"
                        "  stats auth admin:hunter2\nuserlist u\n  user bob insecure-password pw1\n")
    for secret in ("s3cr3t", "hunter2", "pw1"):
        assert secret not in out
    assert "stats auth admin:<redacted:" in out


def test_redactor_continuation_line():
    r = Redactor("x")
    out = r.conf_text("[x]\npassword = abc\\\ndef\nother = 1\n")
    assert "abc" not in out and "def" not in out and "other = 1" in out


def test_remote_script_is_self_contained():
    # Must be runnable from stdin with nothing else from the package available.
    assert "from shx" not in REMOTE_SCRIPT.read_text()
    assert os.path.getsize(REMOTE_SCRIPT) < 64 * 1024


def test_local_only_apps_skip_stock_default_content(splunk_home):
    tar, manifest = open_snapshot(run_remote(splunk_home, "--local-only-app", "big_vendor_*").stdout)
    names = set(tar.getnames())
    es = "etc/apps/SplunkEnterpriseSecuritySuite"
    assert f"{es}/default/app.conf" in names
    assert f"{es}/local/savedsearches.conf" in names
    assert f"{es}/default/savedsearches.conf" not in names
    paths = {f["path"] for f in manifest["files"]}
    assert f"{es}/appserver/static/bundle.js" not in paths
    assert f"{es}/lookups/threat.csv" in paths  # indexed, not copied
    assert "etc/apps/SA-ThreatIntelligence/default/inputs.conf" not in names
    assert "etc/shcluster/apps/DA-ESS-NetworkProtection/default/macros.conf" not in names
    assert "etc/apps/big_vendor_app/default/props.conf" not in names  # extra pattern
    # ES-generated indexer TA and look-alike customer apps are collected in full.
    assert "etc/apps/Splunk_TA_ForIndexers/default/props.conf" in names
    assert "etc/apps/SA-acme/default/props.conf" in names
    summary = manifest["local_only_apps"][es]
    assert summary["files"] == 5 and summary["bytes"] > 100000


def test_btool_drops_stock_lines_of_local_only_apps(splunk_home):
    tar, manifest = open_snapshot(run_remote(splunk_home).stdout)
    btool = text(tar, "btool/savedsearches.txt")
    assert "[ES stock search]" in btool and "disabled = 1" in btool
    assert "search = index=*" not in btool
    assert manifest["btool"]["savedsearches"]["dropped_local_only_default_lines"] == 1


def test_smartstore_credentials_redacted(splunk_home):
    tar, _ = open_snapshot(run_remote(splunk_home).stdout)
    conf = text(tar, "etc/manager-apps/org_all_indexes/local/indexes.conf")
    assert "AKIAABCDEFGHIJKLMNOP" not in conf and "wJalrXUtnFEMI" not in conf
    assert "remote.s3.endpoint = https://s3.example.com" in conf
    assert "path = s3://bucket/splunk" in conf


def test_app_inventory_versions_and_fingerprints(splunk_home):
    write(splunk_home / "etc" / "apps" / "TA-acme" / "local" / "app.conf", "[install]\nstate = disabled\n")
    write(splunk_home / "etc" / "apps" / "TA-manifest" / "app.manifest",
          json.dumps({"info": {"id": {"name": "TA-manifest", "version": "4.0.0"}}}))
    _, manifest = open_snapshot(run_remote(splunk_home).stdout)
    apps = {(a["root"], a["name"]): a for a in manifest["apps"]}

    acme = apps[("apps", "TA-acme")]
    assert acme["version"] == "1.2.3" and acme["state"] == "disabled"
    assert acme["local_only"] is None and acme["content_sha"] and acme["local_files"] == 4
    es = apps[("apps", "SplunkEnterpriseSecuritySuite")]
    assert es["version"] == "7.3.1" and es["local_only"] == "SplunkEnterpriseSecuritySuite"
    assert es["content_sha"] is None and es["content_shape"]
    assert apps[("apps", "TA-manifest")]["manifest_version"] == "4.0.0"
    assert ("deployment-apps", "org_all_outputs") in apps
    assert ("shcluster/apps", "DA-ESS-NetworkProtection") in apps


def test_local_changes_do_not_change_content_fingerprint(splunk_home):
    _, before = open_snapshot(run_remote(splunk_home).stdout)
    write(splunk_home / "etc" / "apps" / "TA-acme" / "local" / "props.conf", "[acme]\nX = 1\n")
    _, after = open_snapshot(run_remote(splunk_home).stdout)
    pick = lambda m: next(a for a in m["apps"] if a["name"] == "TA-acme")
    assert pick(before)["content_sha"] == pick(after)["content_sha"]
    assert pick(before)["local_sha"] != pick(after)["local_sha"]


def test_minimal_install_without_smartstore(tmp_path):
    # Single indexer on local disk: no S3, no staged app roots, no btool, no keepalived.
    home = tmp_path / "splunk"
    write(home / "etc" / "splunk.version", "VERSION=9.0.5\n")
    write(home / "etc" / "auth" / "splunk.secret", "x\n")
    write(home / "etc" / "apps" / "org_all_indexes" / "local" / "indexes.conf",
          "[firewall]\nhomePath = volume:hot/firewall/db\ncoldPath = volume:cold/firewall/colddb\n"
          "thawedPath = $SPLUNK_DB/firewall/thaweddb\nmaxTotalDataSizeMB = 500000\n")
    tar, manifest = open_snapshot(run_remote(home, "--no-btool").stdout)
    assert "etc/apps/org_all_indexes/local/indexes.conf" in tar.getnames()
    assert manifest["errors"] == []
    assert [a["name"] for a in manifest["apps"]] == ["org_all_indexes"]


def test_redaction_marks_encrypted_vs_cleartext():
    r = Redactor("x")
    out = r.conf_text(f"[a]\npassword = {ENC}\n[b]\npassword = hunter22\n")
    assert "password = <redacted:enc:" in out and "password = <redacted:plain:" in out
    assert "hunter22" not in out
