"""exclude_apps: environment-specific apps left out of detail collection and the report."""

import pytest

from runbuilder import app, bt, detail, make_run
from shx.apps import differing_apps
from shx.collect.environment import EnvironmentError_, load
from shx.report.html import render
from shx.report.model import build

NAMES = ("dna_dac_sync", "dac_sync", "corp_dna_dac_sync")

SERVERS = {
    "sh1": {"role": "sh", "site": "site1",
            "apps": [app(n, "1", content="a") for n in NAMES] + [app("TA-x", "1", content="a")],
            "detail": [detail("TA-x", settings=[("default", "props", "x", "A", "1")])],
            "btool": {"server": bt("etc/apps/dac_sync/local/server.conf", "general", sessionTimeout="8h")
                      + bt("etc/system/local/server.conf", "general", serverName="sh1")}},
    "sh2": {"role": "sh", "site": "site2",
            "apps": [app(n, "2", content="b") for n in NAMES] + [app("TA-x", "2", content="b")],
            "detail": [detail("TA-x", settings=[("default", "props", "x", "A", "2")])],
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="sh2",
                                   sessionTimeout="1h")}},
}


def test_differing_apps_skips_excluded():
    summaries = {n: {"apps": s["apps"]} for n, s in SERVERS.items()}
    assert set(differing_apps(summaries)["sh1"]) == {f"apps/{n}" for n in (*NAMES, "TA-x")}
    assert differing_apps(summaries, ["*dac_sync"]) == {"sh1": ["apps/TA-x"], "sh2": ["apps/TA-x"]}


def test_report_uses_run_json_exclusions(tmp_path):
    r = build(make_run(tmp_path, SERVERS, exclude_apps=["*dac_sync"]))
    assert [a.name for a in r.apps] == ["TA-x"]
    rows = {(x.stanza, x.key): x for x in r.system}
    # sessionTimeout is set by dac_sync on sh1: shown only for sh2, sh1 marked as excluded app.
    assert rows[("general", "sessionTimeout")].values["sh1"] == "hariç app"
    assert "*dac_sync" in render(r)


def test_env_file_overrides_without_recollecting(tmp_path):
    run_dir = make_run(tmp_path, SERVERS)  # collected without exclusions
    assert len(build(run_dir).apps) == 4
    env = tmp_path / "e.toml"
    env.write_text('name="test"\nexclude_apps=["*dac_sync"]\n[[servers]]\nname="sh1"\nhost="a"\nrole="sh"\nsite="site1"\n'
                   '[[servers]]\nname="sh2"\nhost="b"\nrole="sh"\nsite="site2"\n')
    assert [a.name for a in build(run_dir, env).apps] == ["TA-x"]


def test_exclude_apps_must_be_a_list(tmp_path):
    env = tmp_path / "e.toml"
    env.write_text('name="t"\nexclude_apps="dac_sync"\n')
    with pytest.raises(EnvironmentError_, match="exclude_apps"):
        load(env)
