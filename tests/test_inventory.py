import tomllib

from runbuilder import app, bt, make_run
from shx.inventory import inventory_cli
from shx.inventory.inputs import input_rows, keepalived_instances, parse_keepalived, suggest
from shx.rules import cli as findings_cli
from shx.rules.context import RunContext

KEEPALIVED = """! Configuration File for keepalived
vrrp_script chk_splunk {
    script "/usr/bin/curl -sk https://127.0.0.1:8089"
}
vrrp_instance VI_SYSLOG {
    state {state}
    interface eth0
    virtual_router_id 51
    priority {prio}
    authentication {
        auth_type PASS
        auth_pass <redacted:plain:abc>
    }
    virtual_ipaddress {
        10.0.1.100/24 dev eth0
    }
    track_script {
        chk_splunk
    }
}
"""

SYSLOG = bt("etc/apps/TA-syslog/default/inputs.conf", "udp://514", sourcetype="syslog", index="network")
HEC = bt("etc/apps/splunk_httpinput/local/inputs.conf", "http://fw", token="<redacted:plain:x>", index="fw")
POLL = bt("etc/apps/TA-poll/local/inputs.conf", "script://./bin/poll.sh", interval="300", sourcetype="poll")
MON = bt("etc/apps/TA-nix/local/inputs.conf", "monitor:///var/log/messages", sourcetype="syslog")
OFF = bt("etc/apps/TA-old/default/inputs.conf", "script://./bin/old.sh", disabled="1")
DBX = bt("etc/apps/splunk_app_db_connect/local/db_inputs.conf", "orders", connection="erp", interval="60")


def servers(both_poll=False):
    ka = lambda st, pr: KEEPALIVED.replace("{state}", st).replace("{prio}", pr)
    return {
        "hf1a": {"role": "hf", "site": "site1", "apps": [app("TA-syslog")],
                 "btool": {"inputs": SYSLOG + HEC + MON + (POLL if both_poll else "")},
                 "files": {"system/keepalived.conf": ka("MASTER", "101")}},
        "hf1b": {"role": "hf", "site": "site1", "apps": [app("TA-syslog"), app("TA-poll")],
                 "btool": {"inputs": SYSLOG + HEC + POLL + OFF, "db_inputs": DBX},
                 "files": {"system/keepalived.conf": ka("BACKUP", "100")}},
        "hf2a": {"role": "hf", "site": "site2", "btool": {"inputs": SYSLOG},
                 "files": {"system/keepalived.conf": ka("MASTER", "101").replace("10.0.1.100", "10.0.2.100")}},
        "sh1": {"role": "sh", "site": "site1"},
    }


def test_parse_keepalived():
    [inst] = parse_keepalived("hf1a", KEEPALIVED.replace("{state}", "MASTER").replace("{prio}", "101"))
    assert (inst.name, inst.state, inst.router_id, inst.priority, inst.vips) == (
        "VI_SYSLOG", "MASTER", "51", "101", ["10.0.1.100"])


def test_input_rows_classify_and_flag(tmp_path):
    ctx = RunContext(make_run(tmp_path, servers()))
    rows, missing = input_rows(ctx)
    by = {(r["server"], r["stanza"]): r for r in rows}
    assert by[("hf1a", "udp://514")]["kind"] == "push" and by[("hf1a", "udp://514")]["index"] == "network"
    assert by[("hf1b", "script://./bin/poll.sh")]["kind"] == "pull"
    assert by[("hf1b", "script://./bin/poll.sh")]["app"] == "TA-poll"
    assert by[("hf1b", "db_inputs://orders")]["connection"] == "erp"
    assert by[("hf1b", "script://./bin/old.sh")]["enabled"] is False
    assert by[("hf1a", "monitor:///var/log/messages")]["kind"] == "local"
    assert missing == ["sh1"]


def test_suggestions_from_keepalived_and_inputs(tmp_path):
    ctx = RunContext(make_run(tmp_path, servers()))
    rows, _ = input_rows(ctx)
    s = suggest(ctx, rows, keepalived_instances(ctx))
    assert s.ha_groups == {"site1-vi-syslog": ["hf1a", "hf1b"]}
    assert s.vips == ["10.0.1.100", "10.0.2.100"]
    assert s.pull_apps == {"hf1b": ["TA-poll", "splunk_app_db_connect"]}  # disabled TA-old not suggested
    assert s.duplicate_pull == []
    assert any("hf2a" in n and "no collected peer" in n for n in s.notes)


def test_duplicate_pull_warned(tmp_path):
    ctx = RunContext(make_run(tmp_path, servers(both_poll=True)))
    rows, _ = input_rows(ctx)
    s = suggest(ctx, rows, keepalived_instances(ctx))
    assert ("script://./bin/poll.sh", ["hf1a", "hf1b"]) in s.duplicate_pull


def test_cli_then_env_override_without_recollecting(tmp_path):
    run_dir = make_run(tmp_path, servers())
    assert inventory_cli.main([str(run_dir)]) == 0
    reports = run_dir / "reports"
    toml = (reports / "suggested_env.toml").read_text()
    assert 'ha_group = "site1-vi-syslog"' in toml and 'pull_apps = ["TA-poll", "splunk_app_db_connect"]' in toml
    parsed = tomllib.loads(toml)
    assert parsed["suggested"]["hf1b"]["pull_apps"] == ["TA-poll", "splunk_app_db_connect"]
    assert parsed["vips"] == ["10.0.1.100", "10.0.2.100"]
    md = (reports / "inventory.md").read_text()
    assert "## Pull inputs" in md and "db_inputs://orders" in md and "VI_SYSLOG MASTER 10.0.1.100" in md

    # Without groups: no HA findings. With the suggestions applied via --env: HA rules run.
    env = tmp_path / "env.toml"
    env.write_text('name="t"\nvips=["10.0.1.100","10.0.2.100"]\n'
                   '[[servers]]\nname="hf1a"\nhost="10.0.1.21"\nrole="hf"\nsite="site1"\nha_group="site1-vi-syslog"\n'
                   '[[servers]]\nname="hf1b"\nhost="10.0.1.22"\nrole="hf"\nsite="site1"\nha_group="site1-vi-syslog"\n'
                   'pull_apps=["TA-poll","splunk_app_db_connect"]\n')
    assert findings_cli.main([str(run_dir), "--env", str(env), "--out", str(tmp_path / "r2")]) == 0
    import json
    rules = {r["rule"]: r for r in json.loads((tmp_path / "r2" / "findings.json").read_text())["rules"]}
    assert rules["HA-003"]["status"] == "ran" and rules["HA-003"]["findings"] == 1  # one low co-located finding
