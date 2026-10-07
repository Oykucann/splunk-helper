import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from shx.collect import cli, rest_collect
from shx.collect.environment import EnvironmentError_, load
from shx.collect.searches import SEARCHES, indexes_search
from shx.transport.rest import GuardError, RestClient, check_request, check_spl, mask_text

BASIC = __import__("base64").b64encode(b"shx:pa55").decode()

# --- guards ---------------------------------------------------------------------------


@pytest.mark.parametrize("spl", [
    "index=x | collect index=summary",
    "index=x | stats count | outputlookup foo.csv",
    "| makeresults | map search=\"search index=x\"",
    "index=x [ search index=y | outputlookup z.csv | fields host ]",
    "index=x | `some_macro`",
    "| delete",
    "index=x | sendemail to=a@b",
    "| savedsearch nightly_summary",
])
def test_spl_guard_denies(spl):
    with pytest.raises(GuardError):
        check_spl(spl)


@pytest.mark.parametrize("spl", [
    'index=x "a | collect b"',
    "index=_internal | stats count BY host",
    indexes_search(None), indexes_search([]), indexes_search(["idx1", "idx2"]),
    *[s.spl for s in SEARCHES],
])
def test_spl_guard_allows_catalog_and_quoted_pipes(spl):
    check_spl(spl)


@pytest.mark.parametrize("method,path,form", [
    ("POST", "/services/saved/searches", {"name": "x"}),
    ("POST", "/services/search/jobs", {"search": "search x", "exec_mode": "normal"}),
    ("POST", "/services/search/jobs", {"search": "search x | collect index=a", "exec_mode": "oneshot"}),
    ("DELETE", "/services/search/jobs/123", None),
    ("GET", "/en-US/account/logout", None),
])
def test_request_guard_denies(method, path, form):
    with pytest.raises(GuardError):
        check_request(method, path, form)


def test_mask_text():
    assert mask_text("login failed password=hunter2 user=bob") == "login failed password=<redacted> user=bob"
    assert "abc123" not in mask_text("Authorization: Bearer abc123")


# --- fake Splunk ------------------------------------------------------------------------

class FakeSplunk:
    def __init__(self, capabilities=("search", "rest_properties_get")):
        self.capabilities = list(capabilities)
        self.requests = []
        self.fail_search_containing = "dbx_job_metrics"

    def handle(self, method, path, query, form):
        self.requests.append((method, path, form))
        if path == "/services/authentication/current-context":
            return 200, {"entry": [{"content": {"username": "shx", "roles": ["shx_ro"],
                                                "capabilities": self.capabilities}}]}
        if path == "/services/server/info":
            return 200, {"entry": [{"content": {"serverName": "sh01", "version": "9.1.2",
                                                "server_roles": ["search_head"]}}]}
        if path == "/services/search/distributed/peers":
            return 200, {"entry": [
                {"name": "idx01:8089", "content": {"peerName": "idx01", "status": "Up"}},
                {"name": "10.0.1.21:8089", "content": {"peerName": "hf01a-splunk", "status": "Up"}},
            ]}
        if path == "/services/search/jobs" and method == "POST":
            if self.fail_search_containing in form["search"]:
                return 400, {"messages": [{"type": "FATAL", "text": "boom"}]}
            return 200, {"results": [{"sample": "token=abcd1234 failed", "count": "1"}], "messages": []}
        return 404, {}


@pytest.fixture
def fake_splunk():
    fake = FakeSplunk()

    class Handler(BaseHTTPRequestHandler):
        def _go(self, method):
            parsed = urllib.parse.urlparse(self.path)
            form = None
            if method == "POST":
                body = self.rfile.read(int(self.headers["Content-Length"])).decode()
                form = dict(urllib.parse.parse_qsl(body))
            assert self.headers["Authorization"] in ("Bearer t0ken", "Basic " + BASIC)
            code, payload = fake.handle(method, parsed.path, parsed.query, form)
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fake.port = server.server_address[1]
    yield fake
    server.shutdown()


def env_file(tmp_path, port, extra=""):
    p = tmp_path / "e.toml"
    p.write_text(f'''name = "t"
[[servers]]
name = "sh01"
host = "127.0.0.1"
role = "sh"
site = "site1"
rest_scheme = "http"
rest_port = {port}
rest_token_env = "SHX_TEST_TOKEN"
{extra}
[[servers]]
name = "hf01a"
host = "10.0.1.21"
role = "hf"
site = "site1"
ha_group = "g"
''')
    return p


def test_collect_excludes_hf_peers_and_masks(fake_splunk, tmp_path, monkeypatch):
    monkeypatch.setenv("SHX_TEST_TOKEN", "t0ken")
    env = load(env_file(tmp_path, fake_splunk.port))
    sh = env.servers[0]
    result = rest_collect.collect(sh, env)

    assert [p["name"] for p in result["search_peers"]["excluded_hf"]] == ["hf01a-splunk"]
    idx_spl = result["searches"]["indexes"]["spl"]
    assert "splunk_server=idx01" in idx_spl and "hf01a" not in idx_spl and "splunk_server=*" not in idx_spl
    assert result["searches"]["exec_errors"]["results"][0]["sample"] == "token=<redacted> failed"
    # One failing search does not stop the rest.
    assert result["searches"]["dbx_jobs"]["ok"] is False
    assert result["searches"]["blocked_queues"]["ok"] is True
    methods = {(m, p) for m, p, _ in fake_splunk.requests}
    assert methods <= {("GET", "/services/authentication/current-context"), ("GET", "/services/server/info"),
                       ("GET", "/services/search/distributed/peers"), ("POST", "/services/search/jobs")}
    assert all(f["exec_mode"] == "oneshot" for m, _, f in fake_splunk.requests if m == "POST")


def test_privileged_token_refused_unless_opted_in(fake_splunk, tmp_path, monkeypatch):
    monkeypatch.setenv("SHX_TEST_TOKEN", "t0ken")
    fake_splunk.capabilities.append("admin_all_objects")
    env = load(env_file(tmp_path, fake_splunk.port))
    with pytest.raises(rest_collect.RestRefused, match="admin_all_objects"):
        rest_collect.collect(env.servers[0], env)
    assert not [r for r in fake_splunk.requests if r[0] == "POST"]

    env = load(env_file(tmp_path, fake_splunk.port, "allow_privileged_token = true"))
    assert rest_collect.collect(env.servers[0], env)["context"]["privileged_capabilities"] == ["admin_all_objects"]


def test_cli_rest_only_writes_results(fake_splunk, tmp_path, monkeypatch):
    monkeypatch.setenv("SHX_TEST_TOKEN", "t0ken")
    p = env_file(tmp_path, fake_splunk.port)
    out = tmp_path / "snaps"
    assert cli.main([str(p), "--rest-only", "--out", str(out)]) == 1  # dbx_jobs fails in the fake
    run_dir = next((out / "t").iterdir())
    run = json.loads((run_dir / "run.json").read_text())
    assert run["servers"]["sh01"]["rest"]["failed"] == ["dbx_jobs"]
    assert "hf01a" not in run["servers"]  # REST never targets an HF
    saved = json.loads((run_dir / "sh01.rest.json").read_text())
    assert "t0ken" not in (run_dir / "sh01.rest.json").read_text()
    assert set(saved["searches"]) == {"indexes", *(s.id for s in SEARCHES)}


def test_cli_check_reports_rest_context(fake_splunk, tmp_path, monkeypatch):
    monkeypatch.setenv("SHX_TEST_TOKEN", "t0ken")
    assert cli.main([str(env_file(tmp_path, fake_splunk.port)), "--check", "--rest-only"]) == 0


def test_rest_token_on_hf_or_in_defaults_rejected(tmp_path):
    p = tmp_path / "e.toml"
    p.write_text('name="t"\n[[servers]]\nname="hf"\nhost="h"\nrole="hf"\nrest_token_env="X"\n')
    with pytest.raises(EnvironmentError_, match="only allowed on search heads"):
        load(p)
    p.write_text('name="t"\n[defaults]\nrest_token_env="X"\n[[servers]]\nname="sh"\nhost="h"\nrole="sh"\n')
    with pytest.raises(EnvironmentError_, match="unknown keys in \\[defaults\\]"):
        load(p)


def test_client_refuses_before_sending():
    sent = []
    client = RestClient("https://x:8089", "t", opener=lambda *a, **k: sent.append(a))
    with pytest.raises(GuardError):
        client.oneshot("index=x | outputlookup a.csv")
    assert not sent
