"""Lab topology: the search head is also the cluster manager."""

import pytest

from runbuilder import app, bt, make_run
from shx.collect import cli
from shx.collect.environment import EnvironmentError_, load
from shx.rules.base import REGISTRY, run_rules
from shx.rules.context import RunContext

ENV = '''name = "lab"
[[servers]]
name = "shcm01"
host = "10.0.0.10"
role = "sh"
also_roles = ["cm"]
site = "site1"
rest_token_env = "X"
[[servers]]
name = "hf01"
host = "10.0.0.20"
role = "hf"
site = "site1"
'''


def test_env_loads_and_collects_once(tmp_path, capsys):
    p = tmp_path / "lab.toml"
    p.write_text(ENV)
    env = load(p)
    sh = env.servers[0]
    assert sh.roles == ("sh", "cm") and sh.rest_enabled
    assert cli.main([str(p), "--dry-run", "--no-rest"]) == 0
    out = capsys.readouterr().out
    assert out.count("10.0.0.10") == 1 and "shcm01 (sh+cm)" in out


@pytest.mark.parametrize("extra", ['also_roles = ["sh"]', 'also_roles = ["cm", "cm"]', 'also_roles = ["uf"]',
                                   'also_roles = ["hf"]'])
def test_invalid_also_roles(tmp_path, extra):
    p = tmp_path / "lab.toml"
    p.write_text(ENV.replace('also_roles = ["cm"]', extra))
    with pytest.raises(EnvironmentError_):
        load(p)


def test_rules_see_both_roles_and_report_topology(tmp_path):
    servers = {
        "shcm01": {"role": "sh", "also_roles": ["cm"], "site": "site1",
                   "apps": [app("org_search", local="L", local_files=2),
                            app("org_all_indexes", root="manager-apps")],
                   "btool": {"props": bt("etc/apps/TA-fw/default/props.conf", "fw", TIME_FORMAT="%s")}},
        "hf01": {"role": "hf", "site": "site1", "btool": {"props": bt("etc/system/default/props.conf", "default")}},
    }
    ctx = RunContext(make_run(tmp_path, servers))
    assert [s.name for s in ctx.servers("cm")] == ["shcm01"] == [s.name for s in ctx.servers("sh")]
    res = {r.rule: r for r in run_rules(ctx, REGISTRY)}
    assert [(f.target, f.severity) for f in res["TOPO-001"].findings] == [("shcm01 / sh+cm", "info")]
    assert res["SHC-001"].findings  # SH rules still apply
    assert "sh+cm shcm01" in res["DATA-001"].findings[0].title


def test_single_role_environment_unchanged(tmp_path):
    ctx = RunContext(make_run(tmp_path, {"sh1": {"role": "sh", "site": "site1"}}))
    res = {r.rule: r for r in run_rules(ctx, REGISTRY)}
    assert res["TOPO-001"].status == "not_applicable"
