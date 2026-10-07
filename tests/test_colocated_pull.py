"""Keepalived pair where one node also runs DB Connect / scripted inputs on its own address."""

import pytest

from runbuilder import app, bt, make_run
from shx.collect.environment import EnvironmentError_, load
from shx.rules.base import REGISTRY, run_rules
from shx.rules.context import RunContext

SYSLOG = bt("etc/apps/TA-syslog/default/inputs.conf", "udp://514", sourcetype="syslog")
DBX_IN = bt("etc/apps/splunk_app_db_connect/local/db_inputs.conf", "orders", connection="erp")
POLL = bt("etc/apps/TA-poll/local/inputs.conf", "script://./bin/poll.sh", interval="60")


def pair(hf1b_inputs, hf1b_pull_apps, hf1a_inputs=""):
    common = [app("TA-syslog")]
    return {
        "hf1a": {"role": "hf", "site": "site1", "ha": "g", "apps": common,
                 "btool": {"inputs": SYSLOG + hf1a_inputs}},
        "hf1b": {"role": "hf", "site": "site1", "ha": "g", "pull_apps": hf1b_pull_apps,
                 "apps": common + [app("splunk_app_db_connect", "3.9.0"), app("TA-poll")],
                 "btool": {"inputs": SYSLOG + hf1b_inputs, "db_inputs": DBX_IN}},
    }


def findings(tmp_path, servers):
    res = {r.rule: r for r in run_rules(RunContext(make_run(tmp_path, servers)), REGISTRY)}
    return {rid: [(f.target, f.severity) for f in r.findings] for rid, r in res.items()}


def test_declared_pull_role_is_low_and_not_drift(tmp_path):
    f = findings(tmp_path, pair(POLL, ["splunk_app_db_connect", "TA-poll"]))
    assert f["HA-003"] == [("g / hf1b / colocated-pull", "low")]
    assert f["HA-001"] == [] and f["HA-002"] == []


def test_undeclared_pull_inputs_stay_high(tmp_path):
    f = findings(tmp_path, pair(POLL, []))
    assert ("hf1b / script://./bin/poll.sh", "high") in f["HA-003"]
    assert ("hf1b / db_inputs://orders", "high") in f["HA-003"]
    assert any(t.endswith("splunk_app_db_connect / presence") for t, _ in f["HA-002"])


def test_partly_declared_flags_only_the_undeclared_app(tmp_path):
    f = findings(tmp_path, pair(POLL, ["splunk_app_db_connect"]))
    assert ("hf1b / script://./bin/poll.sh", "high") in f["HA-003"]
    assert ("g / hf1b / colocated-pull", "low") in f["HA-003"]


def test_same_pull_input_on_both_nodes_is_duplicate(tmp_path):
    f = findings(tmp_path, pair(POLL, ["TA-poll", "splunk_app_db_connect"], hf1a_inputs=POLL))
    assert ("g / script://./bin/poll.sh", "high") in f["HA-003"]


def test_pull_apps_only_on_hf(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="t"\n[[servers]]\nname="sh"\nhost="h"\nrole="sh"\npull_apps=["x"]\n')
    with pytest.raises(EnvironmentError_, match="only for heavy forwarders"):
        load(p)
