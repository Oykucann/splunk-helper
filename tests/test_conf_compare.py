import io
import json
import tarfile

import pytest

from shx.conf.btool import parse
from shx.conf.compare import Expectations, compare_all, normalize
from shx.inventory import cli
from shx.snapshot import load_run

H = "/data/splunk/etc"
DEF = f"{H}/system/default"
LOC = f"{H}/system/local"


def btool(*lines):
    return "\n".join(lines) + "\n"


def server_conf(name, site, key_fp, ssl_versions, engine):
    return btool(
        f"{LOC}/server.conf [general]",
        f"{LOC}/server.conf serverName = {name}",
        f"{LOC}/server.conf site = {site}",
        f"{LOC}/server.conf pass4SymmKey = <redacted:{key_fp}>",
        f"{DEF}/server.conf sessionTimeout = 1h",
        f"{LOC}/server.conf [sslConfig]",
        f"{LOC}/server.conf sslVersions = {ssl_versions}",
        f"{LOC}/server.conf sslRootCAPath = /data/splunk/etc/auth/ca.pem",
        f"{LOC}/server.conf serverCert = /data/splunk/etc/auth/{name}.pem",
        f"{LOC}/server.conf [kvstore]",
        f"{LOC}/server.conf storageEngine = {engine}",
    )


SERVERS = {
    "sh1": ("sh", "site1", None, "VERSION=9.1.2", {
        "server": server_conf("sh1", "site1", "aaa", "tls1.2", "wiredTiger"),
        "web": btool(f"{LOC}/web.conf [settings]", f"{LOC}/web.conf enableSplunkWebSSL = true",
                     f"{LOC}/web.conf httpport = 8000"),
        "limits": btool(f"{DEF}/limits.conf [search]", f"{DEF}/limits.conf max_searches_per_cpu = 1",
                        f"{LOC}/limits.conf base_max_searches = 6"),
    }),
    "sh2": ("sh", "site2", None, "VERSION=9.0.5", {
        "server": server_conf("sh2", "site2", "bbb", "*,-ssl2", "mmapv1"),
        "web": btool(f"{LOC}/web.conf [settings]", f"{LOC}/web.conf enableSplunkWebSSL = 1",
                     f"{LOC}/web.conf httpport = 443"),
        "limits": btool(f"{DEF}/limits.conf [search]", f"{DEF}/limits.conf max_searches_per_cpu = 1",
                        f"{H}/apps/org_limits/local/limits.conf base_max_searches = 10"),
    }),
    "hf1a": ("hf", "site1", "site1-push", "VERSION=9.1.2", {
        "server": server_conf("hf1a", "site1", "ccc", "tls1.2", "wiredTiger"),
        "inputs": btool(f"{H}/apps/TA-syslog/local/inputs.conf [udp://514]",
                        f"{H}/apps/TA-syslog/local/inputs.conf sourcetype = syslog"),
        "outputs": btool(f"{H}/apps/org_out/local/outputs.conf [tcpout:primary]",
                         f"{H}/apps/org_out/local/outputs.conf server = idx1:9997,idx2:9997"),
    }),
    "hf1b": ("hf", "site1", "site1-push", "VERSION=9.1.2", {
        "server": server_conf("hf1b", "site1", "ccc", "tls1.2", "wiredTiger"),
        "inputs": btool(f"{H}/apps/TA-syslog/local/inputs.conf [udp://514]",
                        f"{H}/apps/TA-syslog/local/inputs.conf sourcetype = syslog_fw"),
        "outputs": btool(f"{H}/apps/org_out/local/outputs.conf [tcpout:primary]",
                         f"{H}/apps/org_out/local/outputs.conf server = idx1:9997,idx2:9997"),
    }),
    "hf2a": ("hf", "site2", None, "VERSION=9.1.2", {
        "server": server_conf("hf2a", "site2", "ccc", "tls1.2", "wiredTiger"),
        "outputs": btool(f"{H}/apps/org_out/local/outputs.conf [tcpout:primary]",
                         f"{H}/apps/org_out/local/outputs.conf server = idx3:9997"),
    }),
}


@pytest.fixture
def run_dir(tmp_path):
    run = {"servers": {}}
    for name, (role, site, ha, version, confs) in SERVERS.items():
        with tarfile.open(tmp_path / f"{name}.tar.gz", "w:gz") as tar:
            members = {f"btool/{c}.txt": t for c, t in confs.items()}
            members["manifest.json"] = json.dumps({"apps": [], "splunk_version": version,
                                                   "splunk_secret_sha256": "s1"})
            for mname, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(mname)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        run["servers"][name] = {"ok": True, "snapshot": f"{name}.tar.gz", "role": role,
                                "site": site, "ha_group": ha}
    (tmp_path / "run.json").write_text(json.dumps(run))
    return tmp_path


def index(diffs):
    return {(d.level, d.scope, d.conf, d.stanza, d.key): d for d in diffs}


def test_btool_parse_sources_and_continuations():
    conf = parse(btool(f"{LOC}/props.conf [x]", f"{LOC}/props.conf EVAL-a = if(1,\\",
                       f"{LOC}/props.conf   2, 3)", f"{DEF}/props.conf TRUNCATE = 10000"))
    assert conf["x"]["EVAL-a"].value == "if(1,\\\n2, 3)"
    assert conf["x"]["EVAL-a"].source == "etc/system/local/props.conf"
    assert conf["x"]["TRUNCATE"].is_system_default


def test_normalize_booleans_and_whitespace():
    assert normalize("1") == normalize("True") == "true"
    assert normalize("a,  b") == "a, b"


def test_expectations_file_loads_and_matches():
    e = Expectations.load()
    assert e.lookup("server", "general", "serverName").expect == "per_server"
    assert e.lookup("server", "clustering", "pass4SymmKey").expect == "must_match"
    assert e.lookup("limits", "search", "anything").expect == "should_match"


def test_cross_site_search_heads(run_dir):
    d = index(compare_all(load_run(run_dir)))
    key = lambda c, s, k: d.get(("cross_site", "sh", c, s, k))
    assert key("server", "general", "pass4SymmKey").severity == "high"
    assert key("server", "sslConfig", "sslVersions").values == {"site1": "tls1.2", "site2": "*,-ssl2"}
    assert key("server", "kvstore", "storageEngine").severity == "high"
    assert key("web", "settings", "httpport").severity == "high"
    assert key("_instance", "instance", "splunk_version").severity == "high"
    assert key("server", "general", "site").severity == "decision"
    assert key("limits", "search", "base_max_searches").severity == "medium"
    # Not reported: per-server keys, booleans that only differ in spelling, untouched defaults,
    # identical customised values.
    assert key("server", "general", "serverName") is None
    assert key("server", "sslConfig", "serverCert") is None
    assert key("web", "settings", "enableSplunkWebSSL") is None
    assert key("limits", "search", "max_searches_per_cpu") is None
    assert key("server", "sslConfig", "sslRootCAPath") is None


def test_ha_group_compares_inputs(run_dir):
    d = index(compare_all(load_run(run_dir)))
    diff = d[("ha_group", "site1-push", "inputs", "udp://514", "sourcetype")]
    assert diff.severity == "high" and diff.values == {"hf1a": "syslog", "hf1b": "syslog_fw"}
    assert ("ha_group", "site1-push", "outputs", "tcpout:primary", "server") not in d


def test_cross_site_forwarder_outputs_are_a_decision(run_dir):
    d = index(compare_all(load_run(run_dir)))
    diff = d[("cross_site", "hf", "outputs", "tcpout:primary", "server")]
    assert diff.severity == "decision"
    assert diff.values == {"site1": "idx1:9997,idx2:9997", "site2": "idx3:9997"}


def test_report_contains_configuration_section(run_dir):
    assert cli.main([str(run_dir)]) == 0
    report = (run_dir / "reports" / "comparison_report.md").read_text()
    assert "# Configuration" in report and "| high | server | sslConfig | sslVersions |" in report
    assert (run_dir / "reports" / "conf_differences.csv").read_text().startswith("severity,level")
