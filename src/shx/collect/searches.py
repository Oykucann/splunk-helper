"""Search catalog for the search-head REST collection (SPEC-002)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Search:
    id: str
    spl: str
    earliest: str | None
    purpose: str


INDEX_FIELDS = (
    "splunk_server title datatype disabled currentDBSizeMB totalEventCount minTime maxTime "
    "frozenTimePeriodInSecs maxTotalDataSizeMB maxGlobalDataSizeMB maxGlobalRawDataSizeMB "
    "remotePath coldToFrozenDir coldToFrozenScript homePath coldPath thawedPath "
    "homePath.maxDataSizeMB coldPath.maxDataSizeMB repFactor"
)


def indexes_search(peers: list[str] | None) -> str:
    """`| rest` over the given peers only; None means every peer (no HF among them)."""
    base = "| rest splunk_server={peer} /services/data/indexes count=0 datatype=all"
    if peers is None:
        spl = base.format(peer="*")
    elif not peers:
        spl = base.format(peer="local")
    else:
        spl = base.format(peer=peers[0]) + "".join(
            f" | append [{base.format(peer=p)}]" for p in peers[1:])
    return f"{spl} | fields {INDEX_FIELDS}"


SEARCHES = [
    Search("freeze_events",
           'index=_internal sourcetype=splunkd component=BucketMover "will attempt to freeze" '
           "| rex \"candidate='(?<bucket_path>[^']+)'\" "
           '| rex field=bucket_path "[/\\\\](?<index_dir>[^/\\\\]+)[/\\\\](db|colddb|cold)[/\\\\]" '
           "| stats count AS freezes latest(_time) AS last_freeze earliest(_time) AS first_freeze BY host index_dir",
           "-30d", "Buckets frozen (deleted when no archive) per indexer and index directory"),
    Search("sourcetype_by_forwarder",
           "index=_internal source=*metrics.log* group=per_sourcetype_thruput "
           "| stats sum(kb) AS kb sum(ev) AS events latest(_time) AS last_seen earliest(_time) AS first_seen BY host series",
           "-7d", "Which forwarder/indexer processes which sourcetype"),
    Search("host_by_forwarder",
           "index=_internal source=*metrics.log* group=per_host_thruput "
           "| stats sum(kb) AS kb latest(_time) AS last_seen earliest(_time) AS first_seen BY host series",
           "-7d", "Origin hosts per forwarder; same origin via several HFs = possible duplicate"),
    Search("tcpin_connections",
           "index=_internal source=*metrics.log* group=tcpin_connections "
           "| stats latest(_time) AS last_seen sum(kb) AS kb BY host hostname fwdType version os",
           "-7d", "UF/forwarder connections into each receiver"),
    Search("data_last_seen",
           "| tstats latest(_time) AS last_seen count WHERE index=* BY index sourcetype host",
           "-7d", "Data presence per index/sourcetype/host"),
    Search("exec_errors",
           "index=_internal sourcetype=splunkd component=ExecProcessor (log_level=ERROR OR log_level=WARN) "
           '| rex "message from \\"(?<script>[^\\"]+)\\"" '
           "| stats count latest(_time) AS last_seen latest(event_message) AS sample BY host script log_level",
           "-7d", "Scripted/modular inputs writing errors"),
    Search("dbx_jobs",
           "index=_internal sourcetype=dbx_job_metrics "
           "| stats count AS runs count(eval(status!=\"COMPLETED\")) AS not_completed "
           "latest(_time) AS last_run latest(status) AS last_status BY host input_name",
           "-7d", "DB Connect input runs and failures (field names vary by DBX version)"),
    Search("dbx_errors",
           "index=_internal sourcetype=dbx_server* (ERROR OR SEVERE) "
           "| stats count latest(_time) AS last_seen BY host sourcetype",
           "-7d", "DB Connect server errors"),
    Search("blocked_queues",
           "index=_internal source=*metrics.log* group=queue blocked=true "
           "| stats count latest(_time) AS last_seen BY host name",
           "-7d", "Blocked pipeline queues per instance"),
    Search("scheduler_runs",
           "index=_internal sourcetype=scheduler "
           "| stats count latest(_time) AS last_run count(eval(status=\"skipped\")) AS skipped "
           "values(reason) AS skip_reasons BY host app savedsearch_name user",
           "-30d", "Saved search usage and skips"),
    Search("dashboard_views",
           "index=_internal sourcetype=splunk_web_access method=GET uri_path=\"*/app/*/*\" "
           '| rex field=uri_path "/app/(?<app>[^/]+)/(?<view>[^/?]+)" '
           "| stats count latest(_time) AS last_viewed dc(user) AS users BY host app view",
           "-30d", "Dashboard usage"),
]
