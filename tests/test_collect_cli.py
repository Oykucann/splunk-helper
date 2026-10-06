from pathlib import Path

import pytest

from shx.collect import cli
from shx.collect.environment import EnvironmentError_, Server, is_vip, load

EXAMPLE = Path(__file__).resolve().parent.parent / "environments" / "example.toml"


def test_example_environment_loads_and_orders_ha_groups_last():
    env = load(EXAMPLE)
    order = [s.name for s in env.ordered()]
    assert order == ["sh01", "cm01", "ds01", "idx01", "hf-pull01", "hf01a", "hf01b"]


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
    p.write_text('name="e"\n[[servers]]\nname="x"\nhost="h"\nrole="uf"\n')
    with pytest.raises(EnvironmentError_, match="role"):
        load(p)


def test_unknown_only_name_rejected():
    with pytest.raises(EnvironmentError_, match="unknown server"):
        load(EXAMPLE).ordered({"nope"})


def test_ssh_command_shape():
    s = Server(name="hf01a", host="10.0.1.21", role="hf", ssh_user="oyku",
               ssh_options=("-o", "BatchMode=yes"))
    argv = cli.ssh_argv(s, check=False)
    assert argv[:5] == ["ssh", "-T", "-o", "BatchMode=yes", "oyku@10.0.1.21"]
    assert argv[5] == "sudo -n -u splunk /data/splunk/bin/splunk cmd python3 - --splunk-home /data/splunk"
    assert "--check" in cli.ssh_argv(s, check=True)[5]


def test_run_as_empty_means_no_sudo():
    s = Server(name="x", host="h", role="sh", run_as=None)
    assert not cli.remote_command(s, check=False).startswith("sudo")


def test_salt_not_on_command_line():
    s = Server(name="x", host="h", role="sh")
    payload = cli.script_payload("deadbeef")
    assert payload.startswith(b'_INJECTED_SALT = "deadbeef"\n')
    assert "deadbeef" not in " ".join(cli.ssh_argv(s, check=False))


def test_dry_run_prints_commands(capsys):
    assert cli.main([str(EXAMPLE), "--dry-run", "--only", "hf01a"]) == 0
    out = capsys.readouterr().out
    assert "hf01a (hf, site1-push)" in out and "splunk cmd python3 -" in out


def test_local_only_patterns_passed_to_remote():
    s = Server(name="x", host="h", role="sh", local_only_apps=("TA-big *",))
    assert "--local-only-app 'TA-big *'" in cli.remote_command(s, check=False)
