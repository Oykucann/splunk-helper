"""SSH key vs password, REST token vs password (credentials never stored)."""

import json

import pytest

from shx.collect import cli, rest_collect
from shx.collect.environment import EnvironmentError_, Server, load
from test_rest import env_file, fake_splunk  # noqa: F401  (fixture)


def test_ssh_key_mode_default_and_key_file():
    s = Server(name="x", host="h", role="hf")
    assert cli.ssh_auth_options(s) == ["-o", "BatchMode=yes"]
    s = Server(name="x", host="h", role="hf", ssh_key="~/.ssh/lab.pem")
    opts = cli.ssh_auth_options(s)
    assert opts[2] == "-i" and opts[3].endswith("/.ssh/lab.pem") and "~" not in opts[3]


def test_ssh_password_mode_prompts_via_ssh():
    s = Server(name="x", host="h", role="hf", ssh_auth="password")
    argv = cli.ssh_argv(s, check=False)
    assert "BatchMode=yes" not in argv
    assert "PreferredAuthentications=password,keyboard-interactive" in argv


@pytest.mark.parametrize("body,match", [
    ('ssh_auth = "password"\nssh_options = ["-o", "BatchMode=yes"]', "BatchMode"),
    ('ssh_auth = "telnet"', "ssh_auth"),
    ('rest_auth = "password"', "rest_username"),
])
def test_invalid_auth_settings(tmp_path, body, match):
    p = tmp_path / "e.toml"
    p.write_text(f'name="t"\n[[servers]]\nname="sh"\nhost="h"\nrole="sh"\n{body}\n')
    with pytest.raises(EnvironmentError_, match=match):
        load(p)


def test_rest_password_settings_only_on_search_heads(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="t"\n[[servers]]\nname="hf"\nhost="h"\nrole="hf"\nrest_username="u"\n')
    with pytest.raises(EnvironmentError_, match="search heads"):
        load(p)


def test_rest_password_from_env(fake_splunk, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SHX_PW", "pa55")
    rest_collect._PASSWORDS.clear()
    extra = 'rest_auth = "password"\nrest_username = "shx"\nrest_password_env = "SHX_PW"\n'
    p = env_file(tmp_path, fake_splunk.port, extra).read_text().replace('rest_token_env = "SHX_TEST_TOKEN"\n', "")
    (tmp_path / "e.toml").write_text(p)
    env = load(tmp_path / "e.toml")
    assert env.servers[0].rest_enabled
    out = tmp_path / "snaps"
    cli.main([str(tmp_path / "e.toml"), "--rest-only", "--out", str(out)])
    run_dir = next((out / "t").iterdir())
    text = (run_dir / "sh01.rest.json").read_text() + (run_dir / "run.json").read_text()
    assert "pa55" not in text
    assert json.loads((run_dir / "sh01.rest.json").read_text())["context"]["username"] == "shx"


def test_rest_password_prompted_once(monkeypatch):
    rest_collect._PASSWORDS.clear()
    asked = []
    s = Server(name="sh", host="h", role="sh", rest_auth="password", rest_username="u")
    prompt = lambda msg: asked.append(msg) or "pw"
    assert rest_collect.load_password(s, prompt) == "pw"
    assert rest_collect.load_password(s, prompt) == "pw"
    assert asked == ["Splunk password for u@h: "]


def test_client_repr_hides_credentials():
    c = rest_collect.RestClient("https://h:8089", token="secret", username="u")
    assert "secret" not in repr(c) and c._authorization().startswith("Basic ")
