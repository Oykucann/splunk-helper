import io
import json
import tarfile

import pytest

from shx.inventory import cli
from shx.inventory.apps import compare_all
from shx.snapshot import load_run


def app(name, version, sha="c1", local=None, root="apps", state=None, local_only=None):
    return {"name": name, "root": root, "version": version, "content_sha": None if local_only else sha,
            "content_shape": "shape-" + sha, "local_sha": local, "local_files": 1 if local else 0,
            "state": state, "local_only": local_only}


SERVERS = {
    # name: (role, site, ha_group, apps)
    "sh1": ("sh", "site1", None, [app("SplunkEnterpriseSecuritySuite", "7.3.1", local_only="x"),
                                  app("org_search", "1.0")]),
    "sh2": ("sh", "site2", None, [app("SplunkEnterpriseSecuritySuite", "7.2.0", local_only="x")]),
    "hf1a": ("hf", "site1", "site1-push", [app("TA-syslog", "1.0"), app("TA-hec", "1.0"),
                                           app("TA-x", "2.0", sha="aaa"), app("TA-y", "1.0", local="L1")]),
    "hf1b": ("hf", "site1", "site1-push", [app("TA-syslog", "1.1"), app("TA-x", "2.0", sha="bbb"),
                                           app("TA-y", "1.0", local="L2")]),
    "hfp1": ("hf", "site1", None, [app("splunk_app_db_connect", "3.9.0")]),
    "hf2a": ("hf", "site2", "site2-push", [app("TA-syslog", "2.0")]),
    "hf2b": ("hf", "site2", "site2-push", [app("TA-syslog", "2.0")]),
}


@pytest.fixture
def run_dir(tmp_path):
    run = {"environment": "t", "run_id": "r1", "servers": {}}
    for name, (role, site, ha, apps) in SERVERS.items():
        manifest = json.dumps({"apps": apps, "splunk_version": "VERSION=9.1.2"}).encode()
        with tarfile.open(tmp_path / f"{name}.tar.gz", "w:gz") as tar:
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest))
        run["servers"][name] = {"ok": True, "snapshot": f"{name}.tar.gz", "role": role,
                                "site": site, "ha_group": ha}
    run["servers"]["broken"] = {"ok": False, "role": "hf", "site": "site2", "ha_group": None}
    (tmp_path / "run.json").write_text(json.dumps(run))
    return tmp_path


def index(diffs):
    return {(d.level, d.scope, d.app, d.kind): d for d in diffs}


def test_ha_group_differences(run_dir):
    d = index(compare_all(load_run(run_dir)))
    assert d[("ha_group", "site1-push", "TA-syslog", "version")].values == {"hf1a": "1.0", "hf1b": "1.1"}
    assert d[("ha_group", "site1-push", "TA-hec", "presence")].values == {"hf1a": "present", "hf1b": "-"}
    assert ("ha_group", "site1-push", "TA-x", "content") in d
    assert ("ha_group", "site1-push", "TA-y", "local") in d
    assert d[("ha_group", "site1-push", "TA-syslog", "version")].severity == "high"
    assert not [k for k in d if k[0] == "ha_group" and k[1] == "site2-push"]


def test_site_level_ignores_hf_presence_but_not_versions(run_dir):
    d = index(compare_all(load_run(run_dir)))
    assert ("site", "site1/hf", "splunk_app_db_connect", "presence") not in d
    # Already reported at HA-group level, so not repeated per site.
    assert ("site", "site1/hf", "TA-syslog", "version") not in d


def test_cross_site(run_dir):
    d = index(compare_all(load_run(run_dir)))
    assert d[("cross_site", "sh", "SplunkEnterpriseSecuritySuite", "version")].values == {
        "site1": "7.3.1", "site2": "7.2.0"}
    assert d[("cross_site", "sh", "org_search", "presence")].values == {"site1": "present", "site2": "-"}
    assert d[("cross_site", "hf", "TA-syslog", "version")].values == {"site1": "1.0, 1.1", "site2": "2.0"}
    assert d[("cross_site", "hf", "splunk_app_db_connect", "presence")].values["site2"] == "-"


def test_local_only_apps_compared_by_shape(run_dir):
    snaps = load_run(run_dir)
    # Same ES version on both sites, same shape -> no content diff even without content_sha.
    for s in snaps:
        for a in s.apps:
            if a["name"] == "SplunkEnterpriseSecuritySuite":
                a["version"] = "7.3.1"
    d = index(compare_all(snaps))
    assert not [k for k in d if k[2] == "SplunkEnterpriseSecuritySuite"]


def test_cli_writes_reports(run_dir):
    assert cli.main([str(run_dir)]) == 0
    out = run_dir / "reports"
    assert (out / "apps.csv").read_text().count("\n") == 1 + sum(len(v[3]) for v in SERVERS.values())
    report = (out / "comparison_report.md").read_text()
    assert "## HA group members (must be identical)" in report
    assert "| apps | TA-syslog | version | 1.0 | 1.1 |" in report
    assert "broken" not in report
