import io
import json

from runbuilder import app, bt, make_run
from shx.report import cli, splunkbase
from shx.report.html import render
from shx.report.model import build

SVC_ENT = {"installs": [{"home": "/data/splunk", "product": "Splunk Enterprise", "version": "9.1.2",
                         "running": True, "run_user": "splunk",
                         "process_limits": {"Max open files": {"soft": "65536", "hard": "65536"}}}],
           "systemd_units": [{"unit": "Splunkd.service", "enabled": True,
                              "settings": {"LimitNOFILE": "65536", "User": "splunk", "ExecStart": "x"}}],
           "initd_script": False}
SVC_NONE = {"installs": [], "systemd_units": [], "initd_script": False}

SERVERS = {
    "sh1": {"role": "sh", "site": "site1", "service": SVC_ENT,
            "apps": [app("Splunk_TA_windows", "8.9.0", sha="A", local="L", local_files=1), app("org_same", None)],
            "files": {"etc/apps/Splunk_TA_windows/default/props.conf": "[WinEventLog]\nTRUNCATE = 10000\n",
                      "etc/apps/Splunk_TA_windows/local/props.conf": "[WinEventLog]\nKV_MODE = none\n"},
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="sh1",
                                   pass4SymmKey="<redacted:enc:aaa111>")
                      + bt("etc/system/default/server.conf", "kvstore", port="8191"),
                      "web": bt("etc/system/local/web.conf", "settings", httpport="8000")}},
    "hf1": {"role": "hf", "site": "site1", "service": SVC_ENT,
            "apps": [app("Splunk_TA_windows", "9.0.0", sha="B"), app("org_same", None)],
            "files": {"etc/apps/Splunk_TA_windows/default/props.conf": "[WinEventLog]\nTRUNCATE = 20000\n"},
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="hf1",
                                   pass4SymmKey="<redacted:enc:bbb222>")
                      + bt("etc/system/default/server.conf", "kvstore", port="8191")}},
    "box9": {"role": "hf", "site": "site2", "service": SVC_NONE},
}


def fake_lookup(name):
    return {"Splunk_TA_windows": {"latest": "11.0.3", "url": "https://splunkbase.splunk.com/app/742/"}}.get(name)


def test_model(tmp_path):
    r = build(make_run(tmp_path, SERVERS))
    s = {x.name: x for x in r.servers}
    assert s["sh1"].product.startswith("Splunk Enterprise") and "Splunkd.service (enabled)" in s["sh1"].service
    assert "LimitNOFILE=65536" in s["sh1"].limits and "proses nofile=65536/65536" in s["sh1"].limits
    assert s["box9"].product == "Splunk bulunamadı" and "yok" in s["box9"].service

    apps = {a.name: a for a in r.apps}
    win = apps["Splunk_TA_windows"]
    assert win.versions == ["8.9.0", "9.0.0"]
    diffs = {(d.conf, d.stanza, d.key): d.values for d in win.diffs}
    assert diffs[("props", "WinEventLog", "TRUNCATE")] == {"sh1": "10000", "hf1": "20000"}
    assert diffs[("props", "WinEventLog", "KV_MODE")] == {"sh1": "none (local)", "hf1": "—"}
    assert any(n.startswith("Farklı sürümler: 8.9.0 → sh1; 9.0.0 → hf1") for n in win.notes)
    assert apps["org_same"].diffs == []

    sysrows = {(x.conf, x.stanza, x.key): x for x in r.system}
    p4 = sysrows[("server", "general", "pass4SymmKey")]
    assert {p4.values["sh1"], p4.values["hf1"]} == {"secret#1", "secret#2"} and p4.differs
    assert p4.values["box9"] == "toplanmadı"
    assert ("server", "kvstore", "port") not in sysrows  # stock default, not shown
    assert sysrows[("web", "settings", "httpport")].sources == {"sh1": "system/local"}


def test_splunkbase_lookup_and_cache(tmp_path):
    payload = {"results": [{"appid": "Splunk_TA_windows", "path": "https://splunkbase.splunk.com/app/742/",
                            "releases": [{"title": "11.0.2"}, {"title": "11.0.3"}, {"title": "10.0.1"}]}]}
    opener = lambda url, timeout: io.BytesIO(json.dumps(payload).encode())
    assert splunkbase.lookup("Splunk_TA_windows", opener=opener) == {
        "latest": "11.0.3", "url": "https://splunkbase.splunk.com/app/742/"}
    calls = []
    cache = tmp_path / "sb.json"
    def counting(name):
        calls.append(name)
        return fake_lookup(name)
    out = splunkbase.latest_versions(["Splunk_TA_windows", "search", "org_x"], cache, lookup_fn=counting)
    assert out["Splunk_TA_windows"]["latest"] == "11.0.3" and out["org_x"] is None
    assert "search" not in calls  # built-ins are not queried
    splunkbase.latest_versions(["Splunk_TA_windows", "org_x"], cache, lookup_fn=counting)
    assert sorted(calls) == ["Splunk_TA_windows", "org_x"]  # second run served from cache


def test_html_and_cli(tmp_path, monkeypatch):
    run_dir = make_run(tmp_path, SERVERS)
    monkeypatch.setattr(splunkbase, "lookup", lambda name, **k: fake_lookup(name))
    assert cli.main([str(run_dir)]) == 0
    html = (run_dir / "report.html").read_text()
    assert "Sunucular ve Splunk servisi" in html and "App farkları" in html and "Sunucu ayarları (btool)" in html
    assert 'href="https://splunkbase.splunk.com/app/742/">11.0.3</a> (yeni)' in html
    assert "aaa111" not in html and "secret#1" in html
    assert cli.main([str(run_dir), "--offline", "--out", str(tmp_path / "o.html")]) == 0  # cache reused


def test_render_escapes(tmp_path):
    servers = {"sh1": {"role": "sh", "site": "<b>x</b>", "service": SVC_NONE}}
    assert "<b>x</b>" not in render(build(make_run(tmp_path, servers)))
