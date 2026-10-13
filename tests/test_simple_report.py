import io
import json

from runbuilder import app, bt, detail, make_run
from shx.apps import differing_apps
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
            "apps": [app("Splunk_TA_windows", "8.9.0", content="A", local="L1"), app("org_same", None),
                     app("search", "9.1.2", kind="builtin", content="S", local="LS")],
            "detail": [detail("Splunk_TA_windows", settings=[
                ("default", "props", "WinEventLog", "TRUNCATE", "10000"),
                ("local", "props", "WinEventLog", "KV_MODE", "none")], files=[("bin/run.ps1", "aaa")]),
                detail("search", kind="builtin", settings=[
                    ("local", "savedsearches", "mine", "search", "index=a"),
                    ("local", "metadata", "savedsearches/mine", "modtime", "1788787846.7"),
                    ("local", "metadata", "savedsearches/mine", "version", "10.2.6"),
                    ("local", "metadata", "savedsearches/mine", "owner", "admin"),
                    ("local", "app", "install", "is_configured", "1")])],
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="sh1",
                                   pass4SymmKey="<redacted:enc:aaa111>")
                      + bt("etc/system/default/server.conf", "kvstore", port="8191")
                      + bt("etc/system/local/server.conf", "lmpool:auto_generated_pool_enterprise", quota="MAX")
                      + bt("etc/system/local/server.conf", "introspection:generator:disk_objects", acquireExtra_i_data="true"),
                      "web": bt("etc/system/local/web.conf", "settings", httpport="8000")}},
    "hf1": {"role": "hf", "site": "site1", "service": SVC_ENT,
            "apps": [app("Splunk_TA_windows", "9.0.0", content="B"), app("org_same", None),
                     app("search", "9.1.2", kind="builtin", content="S")],
            "detail": [detail("Splunk_TA_windows", settings=[("default", "props", "WinEventLog", "TRUNCATE", "20000")],
                              files=[("bin/run.ps1", "bbb")]),
                       detail("search", kind="builtin")],
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="hf1",
                                   pass4SymmKey="<redacted:enc:bbb222>")
                      + bt("etc/system/default/server.conf", "kvstore", port="8191")}},
    "box9": {"role": "hf", "site": "site2", "service": SVC_NONE},
}


def fake_lookup(name):
    return {"Splunk_TA_windows": {"latest": "11.0.3", "url": "https://splunkbase.splunk.com/app/742/"}}.get(name)


def test_differing_apps_picks_only_differing_copies():
    summaries = {n: {"apps": s.get("apps", [])} for n, s in SERVERS.items()}
    assert differing_apps(summaries) == {
        "sh1": ["apps/Splunk_TA_windows", "apps/search"],
        "hf1": ["apps/Splunk_TA_windows", "apps/search"],
    }


def test_model(tmp_path):
    r = build(make_run(tmp_path, SERVERS))
    s = {x.name: x for x in r.servers}
    assert s["sh1"].product.startswith("Splunk Enterprise") and "Splunkd.service (enabled)" in s["sh1"].service
    assert "LimitNOFILE=65536" in s["sh1"].limits and "proses nofile=65536/65536" in s["sh1"].limits
    assert s["box9"].product == "Splunk bulunamadı" and "yok" in s["box9"].service

    apps = {a.name: a for a in r.apps}
    win = apps["Splunk_TA_windows"]
    assert win.versions == ["8.9.0", "9.0.0"] and not win.identical
    diffs = {(d.conf, d.stanza, d.key): d.values for d in win.diffs}
    assert diffs[("props", "WinEventLog", "TRUNCATE")] == {"sh1": "10000", "hf1": "20000"}
    assert diffs[("props", "WinEventLog", "KV_MODE")] == {"sh1": "none", "hf1": "—"}
    kv = next(d for d in win.diffs if d.key == "KV_MODE")
    assert kv.layers == {"sh1": "local"}
    assert diffs[("dosya", "bin/run.ps1", "")] == {"sh1": "aaa", "hf1": "bbb"}
    assert any(n.startswith("Farklı sürümler: 8.9.0 → sh1; 9.0.0 → hf1") for n in win.notes)
    assert apps["org_same"].identical and apps["org_same"].diffs == []
    search = apps["search"]
    assert search.kind == "builtin" and {c.letter for c in search.copies} == {"A"}  # same shipped content
    assert {(d.stanza, d.key) for d in search.diffs} == {("mine", "search"), ("savedsearches/mine", "owner")}
    assert any("Splunk app: yalnızca local/" in n for n in search.notes)
    assert [a.name for a in r.apps][-1] == "search"  # Splunk's own apps listed last

    sysrows = {(x.conf, x.stanza, x.key): x for x in r.system}
    p4 = sysrows[("server", "general", "pass4SymmKey")]
    assert {p4.values["sh1"], p4.values["hf1"]} == {"secret#1", "secret#2"} and p4.differs
    assert p4.values["box9"] == "toplanmadı"
    assert ("server", "kvstore", "port") not in sysrows  # stock default, not shown
    assert not [k for k in sysrows if k[1].startswith(("lmpool:", "introspection:"))]  # excluded noise
    assert sysrows[("web", "settings", "httpport")].sources == {"sh1": "system/local"}


def test_missing_detail_is_marked(tmp_path):
    servers = {k: dict(v) for k, v in SERVERS.items()}
    servers["hf1"] = {**servers["hf1"], "detail": []}
    win = {a.name: a for a in build(make_run(tmp_path, servers)).apps}["Splunk_TA_windows"]
    assert {d.values["hf1"] for d in win.diffs if d.conf == "props"} == {"alınamadı"}
    assert any(n.startswith("Detayı alınamayanlar: hf1") for n in win.notes)


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


def test_diffs_rendered_per_server_in_conf_form(tmp_path):
    html = render(build(make_run(tmp_path, SERVERS)))
    section = html.split("App farkları", 1)[1]
    assert "<b>sh1</b><pre>default/props.conf\n  [WinEventLog]\n  TRUNCATE = 10000" in section
    assert "local/props.conf\n  [WinEventLog]\n  KV_MODE = none" in section
    assert "metadata/local.meta\n  [savedsearches/mine]\n  owner = admin" in section
    blocks = "".join(x.split("</pre>")[0] for x in section.split("<pre>")[1:])
    assert "modtime" not in blocks and "is_configured" not in blocks and "version =" not in blocks
    assert "Bu ayarlar olmadan: hf1" in section  # hf1 has nothing for search: one line, no empty table
    assert "<table" not in section.split("Sunucu ayarları")[0]
