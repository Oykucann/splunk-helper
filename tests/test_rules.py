import json
from collections import defaultdict

import pytest

from runbuilder import app, bt, make_run
from shx.rules import cli
from shx.rules.base import REGISTRY, run_rules
from shx.rules.context import RunContext

SYSLOG_DEF = "etc/apps/TA-syslog/default/inputs.conf"
GOOD_OUT = bt("etc/apps/org_out/default/outputs.conf", "tcpout:primary",
              indexerDiscovery="cm1", useACK="true", sslRootCAPath="/x/ca.pem")
DC = bt("etc/apps/org_dc/default/deploymentclient.conf", "target-broker:deploymentServer", targetUri="ds1:8089")


def hf_push(name, sourcetype, syslog_version, sha, local=None, extra_inputs=""):
    return {
        "role": "hf", "site": "site1", "ha": "site1-push",
        "apps": [app("TA-syslog", syslog_version, sha=sha, local=local), app("manual_app")],
        "btool": {"inputs": bt(SYSLOG_DEF, "udp://514", sourcetype=sourcetype) + extra_inputs,
                  "outputs": GOOD_OUT, "deploymentclient": DC,
                  "props": bt("etc/system/default/props.conf", "default", TRUNCATE="10000")},
        "files": {"etc/apps/TA-fw/default/props.conf": "[fw]\nTRUNCATE = 10000\n"},
    }


SERVERS = {
    "hf1a": hf_push("hf1a", "syslog", "1.0", "X", local="L1",
                    extra_inputs=bt("etc/apps/TA-poll/local/inputs.conf", "script://./bin/poll.sh", interval="60")),
    "hf1b": hf_push("hf1b", "syslog_fw", "1.1", "Y"),
    "hfp1": {
        "role": "hf", "site": "site1",
        "btool": {"inputs": bt("etc/apps/TA-x/default/inputs.conf", "script://./bin/gone.sh", interval="60")
                  + bt("etc/apps/TA-x/default/inputs.conf", "monitor:///var/log/gone")
                  + bt("etc/apps/TA-x/default/inputs.conf", "monitor:///var/log/old", disabled="1")},
        "path_checks": [
            {"conf": "etc/apps/TA-x/default/inputs.conf", "stanza": "script://./bin/gone.sh", "kind": "script",
             "checked_path": "/data/splunk/etc/apps/TA-x/bin/gone.sh", "wildcard": False, "exists": False},
            {"conf": "etc/apps/TA-x/default/inputs.conf", "stanza": "monitor:///var/log/gone", "kind": "monitor",
             "checked_path": "/var/log/gone", "wildcard": False, "exists": False},
            {"conf": "etc/apps/TA-x/default/inputs.conf", "stanza": "monitor:///var/log/old", "kind": "monitor",
             "checked_path": "/var/log/old", "wildcard": False, "exists": False},
        ],
        "manifest_files": [{"path": "etc/apps/TA-x/bin/poll.sh", "root": "apps", "kind": "script",
                            "suspected_secrets": [{"line": 3, "key": "password"}]}],
    },
    "hf2a": {
        "role": "hf", "site": "site2",
        "btool": {"outputs": bt("etc/apps/org_out/local/outputs.conf", "tcpout:primary", server="idx3:9997",
                                sslVerifyServerCert="false")},
        "files": {"etc/apps/org_out/local/outputs.conf": "[tcpout:primary]\nsslPassword = <redacted:plain:abc>\n",
                  "etc/apps/hec/local/inputs.conf": "[http://app]\ntoken = <redacted:plain:def>\n"},
    },
    "ds1": {
        "role": "ds", "site": "site1",
        "apps": [app("TA-syslog", "1.0", root="deployment-apps", sha="X")],
        "btool": {"serverclass": bt("etc/system/local/serverclass.conf", "serverClass:hf_push",
                                    **{"whitelist__0": "hf1*", "restartSplunkd": "true"})
                  + bt("etc/system/local/serverclass.conf", "serverClass:hf_push:app:TA-syslog")},
    },
    "idx1": {
        "role": "idx", "site": "site1",
        "btool": {"props": bt("etc/peer-apps/TA-fw/default/props.conf", "fw", TIME_FORMAT="%s")},
    },
    "idx2": {
        "role": "idx", "site": "site2",
        "files": {"etc/peer-apps/org_idx/local/indexes.conf": "[fw]\nmaxTotalDataSizeMB = 1000\n"},
    },
    "sh1": {
        "role": "sh", "site": "site1",
        "apps": [app("org_search", local="S", local_files=4),
                 app("SplunkEnterpriseSecuritySuite", "7.3.1", local="E", local_files=9, local_only="x")],
        "manifest_files": [{"path": "etc/users/bob/search/local/savedsearches.conf", "root": "users", "kind": "conf"}],
        "btool": {"server": bt("etc/system/local/server.conf", "sslConfig", sslVersions="tls1.2")},
        "files": {"etc/apps/org_fw/local/props.conf": "[fw]\nTRUNCATE = 0\n"},
    },
    "sh2": {
        "role": "sh", "site": "site2",
        "btool": {"server": bt("etc/system/local/server.conf", "sslConfig", sslVersions="*,-ssl2")},
    },
}

REST = {
    "sh1": {
        "sourcetype_by_forwarder": [{"host": "hf1a", "series": "fw"}],
        "host_by_forwarder": [
            {"host": "hf1a", "series": "fw01", "first_seen": "1", "last_seen": "2"},
            {"host": "hf1a", "series": "web01"}, {"host": "hf1b", "series": "web01"},
        ],
        "exec_errors": [{"host": "hfp1", "script": "python poll.py", "log_level": "ERROR", "count": "12"}],
        "dbx_jobs": [{"host": "hfp1", "input_name": "orders", "not_completed": "3", "runs": "10"}],
        "blocked_queues": [{"host": "hf1a", "name": "typingqueue", "count": "40"}],
        "indexes": [
            {"splunk_server": "idx1", "title": "fw", "currentDBSizeMB": "460000", "frozenTimePeriodInSecs": "188697600",
             "maxTotalDataSizeMB": "500000"},
            {"splunk_server": "idx1", "title": "proxy", "frozenTimePeriodInSecs": "2592000"},
            {"splunk_server": "idx1", "title": "_internal"},
        ],
        "freeze_events": [{"host": "idx1", "index_dir": "proxy", "freezes": "120", "last_freeze": "9"}],
    },
    "sh2": {
        "host_by_forwarder": [{"host": "hf2a", "series": "fw01", "first_seen": "1", "last_seen": "2"}],
        "indexes": [{"splunk_server": "idx2", "title": "fw", "remotePath": "volume:s3/$_index_name",
                     "maxGlobalDataSizeMB": "0", "frozenTimePeriodInSecs": "188697600"}],
    },
}


@pytest.fixture
def results(tmp_path):
    run_dir = make_run(tmp_path, SERVERS, REST)
    return run_dir, run_rules(RunContext(run_dir), REGISTRY)


def targets(results):
    out = defaultdict(set)
    for r in results:
        for f in r.findings:
            out[r.rule].add((f.target, f.severity, f.confidence))
    return out


def test_no_rule_errors(results):
    _, res = results
    assert [(r.rule, r.note) for r in res if r.status == "error"] == []
    not_ran = [(r.rule, r.status) for r in res if r.status != "ran"]
    assert not_ran == [("TOPO-001", "not_applicable")]  # every server has a single role here


def test_ha_rules(results):
    t = targets(results[1])
    assert ("site1-push / inputs / udp://514", "high", "proven") in t["HA-001"]
    assert ("site1-push / apps / TA-syslog / version", "high", "proven") in t["HA-002"]
    assert ("hf1a / script://./bin/poll.sh", "high", "proven") in t["HA-003"]
    assert ("ds1 / hf_push / TA-syslog / site1-push", "high", "proven") in t["HA-004"]


def test_forwarding_rules(results):
    t = targets(results[1])
    assert {x[0] for x in t["FWD-001"]} == {"hf2a / tcpout:primary"}
    assert {x[0] for x in t["FWD-002"]} == {"hf2a / tcpout:primary"}
    assert "hf2a / tcpout:primary" in {x[0] for x in t["FWD-003"]}


def test_data_rules(results):
    t = targets(results[1])
    assert ("site1 / idx1 / fw", "high", "suspected") in t["DATA-001"]
    assert {x[0] for x in t["DATA-002"]} == {"props / fw / TRUNCATE"}
    assert ("origin / fw01", "high", "suspected") in t["DATA-003"]
    assert not [x for x in t["DATA-003"] if "web01" in x[0]]  # same HA group = failover, not duplicate


def test_input_rules(results):
    t = targets(results[1])
    assert t["INP-001"] == {("hfp1 / script://./bin/gone.sh", "high", "proven")}
    assert t["INP-002"] == {("hfp1 / monitor:///var/log/gone", "medium", "proven")}
    assert {x[0] for x in t["INP-003"]} == {"hfp1 / python poll.py"}
    assert "hfp1 / orders" in {x[0] for x in t["INP-004"]}
    assert ("hf1a / queues", "high", "proven") in t["INP-005"]


def test_drift_and_shc(results):
    t = targets(results[1])
    assert {x[0] for x in t["DS-001"]} >= {"hf1a / TA-syslog / local", "hf1b / TA-syslog / content",
                                            "hf1a / manual_app / unmanaged"}
    assert {x[0] for x in t["SHC-001"]} == {"sh1 / local", "sh1 / users"}
    assert ("sh / server / sslConfig", "high", "proven") in t["XS-001"]


def test_security_rules(results):
    t = targets(results[1])
    sec1 = {x[0] for x in t["SEC-001"]}
    assert "hf2a / etc/apps/org_out/local/outputs.conf / tcpout:primary / sslPassword" in sec1
    assert not [x for x in sec1 if "http://" in x]  # HEC token cleartext is by design
    assert {x[0] for x in t["SEC-002"]} == {"hfp1 / etc/apps/TA-x/bin/poll.sh"}
    assert "hf2a / outputs / tcpout:primary" in {x[0] for x in t["SEC-003"]}


def test_retention_rules(results):
    t = targets(results[1])
    assert ("proxy / site1 / deleting", "high", "proven") in t["RET-001"]
    assert ("fw / site1 / near-cap", "high", "suspected") in t["RET-001"]
    assert not [x for x in t["RET-001"] if x[0].startswith("_internal")]
    assert ("fw / site2 / unbounded", "medium", "proven") in t["RET-002"]
    assert not [x for x in t["RET-002"] if x[0].startswith("proxy")]  # 30-day limit is not unbounded
    assert {x[0] for x in t["RET-003"]} == {"fw / site2 / maxTotalDataSizeMB"}
    assert {x[0] for x in t["RET-004"]} == {"storage / mixed"}
    assert ("fw / cross-site", "high", "proven") in t["RET-005"]


def test_minimal_environment_reports_not_applicable(tmp_path):
    run_dir = make_run(tmp_path, {"sh1": {"role": "sh", "site": "site1"}})
    res = {r.rule: r for r in run_rules(RunContext(run_dir), REGISTRY)}
    assert not [r for r in res.values() if r.status == "error"]
    assert res["HA-001"].status == "not_applicable"
    assert res["XS-001"].status == "not_applicable"
    assert res["RET-001"].status == "insufficient_data"
    assert res["DATA-003"].status == "insufficient_data"
    assert sum(len(r.findings) for r in res.values()) == 0


def test_cli_outputs_and_stable_ids(tmp_path):
    run_dir = make_run(tmp_path, SERVERS, REST)
    assert cli.main([str(run_dir)]) == 0
    data = json.loads((run_dir / "reports" / "findings.json").read_text())
    ids = [f["id"] for f in data["findings"]]
    assert len(ids) == len(set(ids))
    assert data["findings"][0]["severity"] == "high"
    md = (run_dir / "reports" / "findings.md").read_text()
    assert "## Rules" in md and "### [HA-004]" in md
    assert cli.main([str(run_dir), "--out", str(tmp_path / "again")]) == 0
    again = json.loads((tmp_path / "again" / "findings.json").read_text())
    assert ids == [f["id"] for f in again["findings"]]
