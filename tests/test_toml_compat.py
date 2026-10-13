"""The fallback TOML reader must match tomllib on every file this project reads."""

import tomllib
from pathlib import Path

import pytest

from shx import _toml
from shx._toml import TOMLDecodeError, _mini_loads

ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / "environments" / "example.toml", ROOT / "src" / "shx" / "knowledge" / "conf_expectations.toml"]

SAMPLES = [
    'name = "t"\nvips = ["10.0.0.1", "10.0.0.2"]  # comment\n',
    '[defaults]\nssh_options = [\n  "-o", "ConnectTimeout=10",  # c\n  "-i", \'~/k.pem\',\n]\ntimeout_seconds = 900\nbtool = true\n',
    '[[servers]]\nname = "a#b"\nrole = "hf"\n[[servers]]\nname = "c"\nallow_privileged_token = false\n',
    '[suggested."hf1b"]\npull_apps = ["TA-poll", "splunk_app_db_connect"]\n',
    'key = "esc \\" \\\\ \\n"\nf = 1.5\nneg = -3\n',
    '',
]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_fallback_matches_tomllib_on_project_files(path):
    text = path.read_text()
    assert _mini_loads(text) == tomllib.loads(text)


@pytest.mark.parametrize("text", SAMPLES)
def test_fallback_matches_tomllib_on_samples(text):
    assert _mini_loads(text) == tomllib.loads(text)


@pytest.mark.parametrize("text", ['a = 1\na = 2\n', 'a = \n', 'a = what\n', 'just text\n'])
def test_fallback_rejects_invalid(text):
    with pytest.raises(TOMLDecodeError):
        _mini_loads(text)


def test_loads_wraps_errors():
    with pytest.raises(TOMLDecodeError):
        _toml.loads("a = 1\na = 2\n")


def test_environment_loads_without_tomllib(monkeypatch):
    from shx.collect.environment import load
    from shx.conf.compare import Expectations
    monkeypatch.setattr(_toml, "_impl", None)
    env = load(FILES[0])
    assert [s.name for s in env.ordered()][0] == "sh01"
    assert Expectations.load().lookup("server", "general", "serverName").expect == "per_server"
