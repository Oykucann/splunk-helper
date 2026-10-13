import csv

from runbuilder import app, bt, make_run
from shx.report import cli
from shx.report.apps import app_settings_table, apps_table
from shx.report.indexes import indexes_table
from shx.report.system import system_table
from shx.rules.context import RunContext


def f(path, sha, kind="script"):
    return {"path": path, "root": path.split("/")[1], "kind": kind, "sha256": sha}


SERVERS = {
    "sh1": {"role": "sh", "site": "site1",
            "apps": [app("TA-fw", "1.0", sha="A", local="L", local_files=1), app("org_same"),
                     app("SplunkEnterpriseSecuritySuite", "7.3.1", local_only="x")],
            "files": {"etc/apps/TA-fw/default/props.conf": "[fw]\nTRUNCATE = 10000\n",
                      "etc/apps/TA-fw/local/props.conf": "[fw]\nKV_MODE = json\n",
                      "etc/apps/org_same/default/props.conf": "[x]\nA = 1\n"},
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="sh1",
                                   pass4SymmKey="<redacted:enc:aaa111>"),
                      "web": bt("etc/system/local/web.conf", "settings", httpport="8000")}},
    "ds1": {"role": "ds", "site": "site1",
            "apps": [app("TA-fw", "1.1", root="deployment-apps", sha="B")],
            "files": {"etc/deployment-apps/TA-fw/default/props.conf": "[fw]\nTRUNCATE = 20000\nTIME_FORMAT = %s\n"},
            "manifest_files": [f("etc/deployment-apps/TA-fw/bin/run.sh", "x" * 64)]},
    "hf1": {"role": "hf", "site": "site1",
            "apps": [app("TA-fw", "1.1", sha="B"), app("org_same")],
            "files": {"etc/apps/TA-fw/default/props.conf": "[fw]\nTRUNCATE = 20000\nTIME_FORMAT = %s\n",
                      "etc/apps/org_same/default/props.conf": "[x]\nA = 1\n"},
            "manifest_files": [f("etc/apps/TA-fw/bin/run.sh", "y" * 64)]},
    "cm1": {"role": "cm", "site": "site1",
            "files": {"etc/manager-apps/org_idx/default/indexes.conf":
                      "[default]\nfrozenTimePeriodInSecs = 7776000\n[fw]\nhomePath = volume:hot/fw/db\n[proxy]\nhomePath = x\n",
                      "etc/manager-apps/org_idx/local/indexes.conf": "[proxy]\nfrozenTimePeriodInSecs = 2592000\n"}},
    "sh2": {"role": "sh", "site": "site2",
            "btool": {"server": bt("etc/system/local/server.conf", "general", serverName="sh2",
                                   pass4SymmKey="<redacted:enc:bbb222>"),
                      "web": bt("etc/system/default/web.conf", "settings", httpport="8000")}},
    "cm2": {"role": "cm", "site": "site2",
            "files": {"etc/manager-apps/org_idx/local/indexes.conf":
                      "[fw]\nhomePath = volume:hot/fw/db\nfrozenTimePeriodInSecs = 31536000\n"
                      "remotePath = volume:s3/$_index_name\n[dns]\nhomePath = y\n[volume:s3]\npath = s3://b\n"}},
}
REST = {"sh1": {"indexes": [{"title": "fw", "splunk_server": "idx1", "currentDBSizeMB": "100", "totalEventCount": "5",
                             "minTime": "2024-01-01", "maxTime": "2026-10-01"},
                            {"title": "fw", "splunk_server": "idx2", "currentDBSizeMB": "50", "totalEventCount": "5",
                             "minTime": "2023-06-01", "maxTime": "2026-10-02"}]}}


def ctx(tmp_path):
    return RunContext(make_run(tmp_path, SERVERS, REST))


def test_apps_matrix(tmp_path):
    rows, cols = apps_table(ctx(tmp_path))
    fw = next(r for r in rows if r["app"] == "TA-fw")
    assert fw["variants"] == 2 and fw["versions"] == "1.0, 1.1"
    assert fw["site1/ds1/deployment-apps"] == "1.1 A" == fw["site1/hf1/apps"]  # same content, same letter
    assert fw["site1/sh1/apps"] == "1.0 B +local"
    assert next(r for r in rows if r["app"] == "org_same")["variants"] == 1
    assert "site1/ds1/deployment-apps" in cols


def test_app_settings_only_differences(tmp_path):
    rows, _ = app_settings_table(ctx(tmp_path))
    by = {(r["app"], r["conf"], r["stanza"], r["key"]): r for r in rows}
    trunc = by[("TA-fw", "props", "fw", "TRUNCATE")]
    assert (trunc["site1/sh1/apps"], trunc["site1/ds1/deployment-apps"], trunc["site1/hf1/apps"]) == \
        ("10000", "20000", "20000")
    assert by[("TA-fw", "props", "fw", "KV_MODE")]["site1/sh1/apps"] == "json [local]"
    assert by[("TA-fw", "props", "fw", "KV_MODE")]["site1/hf1/apps"] == "(unset)"
    script = by[("TA-fw", "(file)", "bin/run.sh", "sha256")]
    assert script["site1/sh1/apps"] == "(missing)" and script["site1/ds1/deployment-apps"] != script["site1/hf1/apps"]
    assert not [k for k in by if k[0] == "org_same"]
    assert "SA-" not in " ".join(r["app"] for r in rows)


def test_system_settings(tmp_path):
    rows, cols = system_table(ctx(tmp_path))
    by = {(r["conf"], r["stanza"], r["key"]): r for r in rows}
    p4 = by[("server", "general", "pass4SymmKey")]
    assert p4["differs"] == "yes"
    assert p4["site1/sh1 (sh)"] == "secret#1 (enc)" and p4["site2/sh2 (sh)"] == "secret#2 (enc)"
    assert p4["site1/ds1 (ds)"] == "(not collected)"
    port = by[("web", "settings", "httpport")]
    assert port["differs"] == "" and port["sources"] == "sh1=system/local"
    assert ("(instance)", "", "splunk_version") in by


def test_indexes_per_site(tmp_path):
    rows, cols = indexes_table(ctx(tmp_path))
    by = {r["index"]: r for r in rows}
    assert set(by) == {"fw", "proxy", "dns"}  # volumes and [default] are not indexes
    assert by["proxy"]["only_in"] == "site1" and by["dns"]["only_in"] == "site2"
    assert by["proxy"]["site1:frozenTimePeriodInSecs"] == "2592000"  # local over default
    assert by["fw"]["site1:frozenTimePeriodInSecs"] == "7776000"     # [default] fills
    assert "frozenTimePeriodInSecs" in by["fw"]["differs"] and "remotePath" in by["fw"]["differs"]
    assert by["fw"]["site1:size_mb"] == "150" and by["fw"]["site1:earliest"] == "2023-06-01"
    assert "cm1:manager-apps/org_idx/default" in by["fw"]["site1:defined_in"]


def test_cli_writes_csvs(tmp_path):
    run_dir = make_run(tmp_path, SERVERS, REST)
    assert cli.main([str(run_dir)]) == 0
    out = run_dir / "reports"
    for name in ("apps.csv", "app_settings.csv", "system_settings.csv", "indexes.csv"):
        with (out / name).open() as fh:
            assert next(csv.reader(fh))  # header present
    md = (out / "report.md").read_text()
    assert "TA-fw: 2 variants" in md and "dns: only in site2" in md
    assert "aaa111" not in (out / "system_settings.csv").read_text()
