from pathlib import Path

import pytest

from shx.collect import cli
from shx.collect.environment import EnvironmentError_, Server, is_vip, load

EXAMPLE = Path(__file__).resolve().parent.parent / "environments" / "example.toml"


def test_example_environment_loads_and_orders_ha_groups_last():
    env = load(EXAMPLE)
    order = [s.name for s in env.ordered()]
    assert order == ["sh01", "ds01", "uf01", "hf01a", "hf01b"]


def test_vip_target_is_refused(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="e"\nvips=["10.0.0.100"]\n[[servers]]\nname="hf"\nhost="10.0.0.100"\nrole="hf"\n')
    with pytest.raises(EnvironmentError_, match="VIP"):
        load(p)


def test_vip_detected_by_resolution():
    table = {"hf-vip.local": {"10.0.0.100"}, "hf01.local": {"10.0.0.100"}}
    assert is_vip("hf01.local", frozenset({"hf-vip.local"}), resolver=lambda h: table.get(h, set()))


def test_unknown_keys_and_roles_rejected(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="e"\n[[servers]]\nname="x"\nhost="h"\nrole="hf"\nrestart=true\n')
    with pytest.raises(EnvironmentError_, match="unknown keys"):
        load(p)
    p.write_text('name="e"\n[[servers]]\nname="x"\nhost="h"\nrole="agent"\n')
    with pytest.raises(EnvironmentError_, match="role"):
        load(p)


def test_unknown_only_name_rejected():
    with pytest.raises(EnvironmentError_, match="unknown server"):
        load(EXAMPLE).ordered({"nope"})


def test_ssh_command_shape():
    s = Server(name="hf01a", host="10.0.1.21", role="hf", ssh_user="oyku",
               ssh_options=("-o", "BatchMode=yes"))
    argv = cli.ssh_argv(s)
    assert argv[:5] == ["ssh", "-T", "-o", "BatchMode=yes", "oyku@10.0.1.21"]
    assert argv[5] == "sudo -n -u splunk /data/splunk/bin/splunk cmd python3 -B - --splunk-home /data/splunk --summary"
    assert "--check" in cli.ssh_argv(s, "check")[5]
    assert cli.ssh_argv(s, "detail", ["apps/TA x"])[5].endswith("--detail --app 'apps/TA x'")


def test_run_as_empty_means_no_sudo():
    s = Server(name="x", host="h", role="sh", run_as=None)
    assert not cli.remote_command(s).startswith("sudo")


def test_salt_not_on_command_line():
    s = Server(name="x", host="h", role="sh")
    payload = cli.script_payload("deadbeef")
    assert payload.startswith(b'_INJECTED_SALT = "deadbeef"\n')
    assert "deadbeef" not in " ".join(cli.ssh_argv(s))


def test_dry_run_prints_commands(capsys):
    assert cli.main([str(EXAMPLE), "--dry-run", "--only", "hf01a"]) == 0
    out = capsys.readouterr().out
    assert "hf01a (hf, site1-syslog)" in out and "splunk cmd python3 -B -" in out


def test_local_only_patterns_passed_to_remote():
    s = Server(name="x", host="h", role="sh", local_only_apps=("TA-big *",))
    assert "--vendor-app 'TA-big *'" in cli.remote_command(s)


def test_uf_uses_system_python_and_legacy_keys_are_ignored(tmp_path, capsys):
    p = tmp_path / "e.toml"
    p.write_text('name="e"\n[defaults]\nrest_verify_tls=false\n[[servers]]\nname="uf1"\nhost="h"\n'
                 'role="uf"\nsplunk_home="/opt/splunkforwarder"\nrun_as="splunkfwd"\n'
                 'rest_token_env="X"\n[[servers]]\nname="sh1"\nhost="h2"\nrole="sh"\n')
    env = load(p)
    assert "ignoring keys no longer used" in capsys.readouterr().err
    uf, sh = env.servers
    assert cli.remote_command(uf).startswith("sudo -n -u splunkfwd python3 -B - ")
    assert "/bin/splunk cmd python3 -B -" in cli.remote_command(sh)
    assert [s.name for s in env.ordered()] == ["sh1", "uf1"]


def test_two_phases_detail_only_where_copies_differ(tmp_path, monkeypatch):
    p = tmp_path / "e.toml"
    p.write_text('name="e"\n[[servers]]\nname="sh1"\nhost="h1"\nrole="sh"\n'
                 '[[servers]]\nname="hf1"\nhost="h2"\nrole="hf"\n[[servers]]\nname="hf2"\nhost="h3"\nrole="hf"\n')
    same = {"name": "org_same", "root": "apps", "version": "1", "content_fp": "x", "local_fp": None}
    diff = lambda fp: {"name": "TA-x", "root": "apps", "version": "1", "content_fp": fp, "local_fp": None}
    summaries = {"sh1": [same, diff("a")], "hf1": [same, diff("b")], "hf2": [same]}
    calls = []

    def fake_run_remote(server, mode, salt, apps=(), timeout=None):
        calls.append((server.name, mode, list(apps)))
        if mode == "summary":
            return {"ok": True, "data": {"apps": summaries[server.name]}, "stderr": ""}
        return {"ok": True, "data": {"apps": [{"name": "TA-x", "root": "apps", "settings": []}]}, "stderr": ""}
    monkeypatch.setattr(cli, "run_remote", fake_run_remote)
    assert cli.main([str(p), "--out", str(tmp_path / "snaps")]) == 0
    assert [c for c in calls if c[1] == "detail"] == [("sh1", "detail", ["apps/TA-x"]),
                                                     ("hf1", "detail", ["apps/TA-x"])]
    run_dir = next((tmp_path / "snaps" / "e").iterdir())
    import json
    run = json.loads((run_dir / "run.json").read_text())
    assert run["servers"]["hf2"].get("detail") is None and run["servers"]["sh1"]["detail"] == "sh1.detail.json"
    assert not list(run_dir.glob("*.tar.gz"))


def test_destination_template(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="e"\nvips=["10.0.1.100"]\n[defaults]\nssh_auth="password"\nssh_user="splunk"\nrun_as=""\n'
                 'ssh_destination="me@{user}@{host}@gateway.example.local"\n'
                 '[[servers]]\nname="hf1"\nhost="10.0.1.21"\nrole="hf"\n')
    [s] = load(p).servers
    argv = cli.ssh_argv(s)
    assert argv[-2] == "me@splunk@10.0.1.21@gateway.example.local"
    assert "BatchMode=yes" not in argv and not argv[-1].startswith("sudo")
    # The VIP guard still applies to the real target address inside the template.
    p.write_text(p.read_text().replace('host="10.0.1.21"', 'host="10.0.1.100"'))
    with pytest.raises(EnvironmentError_, match="VIP"):
        load(p)


def test_destination_template_validated(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="e"\n[[servers]]\nname="x"\nhost="h"\nrole="hf"\nssh_destination="a@gateway"\n')
    with pytest.raises(EnvironmentError_, match="ssh_destination"):
        load(p)
