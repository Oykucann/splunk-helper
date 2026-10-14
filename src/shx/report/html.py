"""Render the report as one self-contained HTML file."""

from __future__ import annotations

from collections import defaultdict
from html import escape

from shx.report.model import KIND_LABEL, NOT_COLLECTED, UNSET, Report

CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--muted:#6e6e73;--line:#e5e5ea;--hi:#fff4d6;--new:#e3f4e8;--head:#f5f5f7}
@media (prefers-color-scheme:dark){:root{--bg:#161618;--fg:#f2f2f7;--muted:#a1a1a6;--line:#38383a;
--hi:#3d3216;--new:#1d3a26;--head:#232326}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;margin:24px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 8px}.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:6px 0 12px}
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
th{background:var(--head);position:sticky;top:0}td.hi{background:var(--hi)}td.new{background:var(--new)}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}code{font-size:12px}
ul{margin:4px 0 8px 18px;padding:0}.wrap{overflow-x:auto}
.srv{margin:8px 0 12px}pre{background:var(--head);border:1px solid var(--line);border-radius:6px;
padding:8px 12px;margin:4px 0;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;
word-break:break-word}
"""


def _e(x) -> str:
    return escape(str(x if x is not None else ""))


def _table(head: list[str], rows: list[str]) -> str:
    return ('<div class="wrap"><table><tr>' + "".join(f"<th>{_e(h)}</th>" for h in head) + "</tr>"
            + "".join(rows) + "</table></div>")


def servers_section(r: Report) -> str:
    rows = [f"<tr><td>{_e(s.name)}</td><td>{_e(s.role)}</td><td>{_e(s.site)}</td><td>{_e(s.product)}</td>"
            f"<td>{_e(s.version)}</td><td>{_e(s.running)}</td><td>{_e(s.service)}</td><td>{_e(s.limits)}</td></tr>"
            for s in r.servers]
    return "<h2>Sunucular ve Splunk servisi</h2>" + _table(
        ["Sunucu", "Rol", "Site", "Ürün", "Sürüm", "Durum", "Servis", "Limitler"], rows)


def os_section(r: Report) -> str:
    rows = []
    for o in r.os:
        thp = f'<td class=hi>{_e(o.thp)}</td>' if not o.thp_off else f"<td>{_e(o.thp)}</td>"
        lim = f"{o.limits} ({o.limits_source})" if o.limits else ""
        lim = f'<td class=hi>{_e(lim)}</td>' if not o.limits_ok else f"<td>{_e(lim)}</td>"
        rows.append(f"<tr><td>{_e(o.name)}</td><td>{_e(o.os)}</td><td>{_e(o.kernel)}</td><td>{_e(o.hardware)}</td>"
                    f"<td>{_e(o.selinux)}</td>{thp}{lim}<td>{_e(o.ntp)}</td><td>{_e(o.dns)}</td></tr>")
    legend = ('<p class="muted">Sarı: Splunk önerisinin dışında (THP kapalı olmalı; nofile ≥ 64000, '
              'nproc ≥ 16000, fsize unlimited). Limitler çalışan splunkd’den, çalışmıyorsa oturumdan alınır.</p>')
    return "<h2>İşletim sistemi</h2>" + legend + _table(
        ["Sunucu", "OS", "Kernel", "Donanım", "SELinux", "THP", "ulimit", "NTP", "DNS"], rows)


def apps_section(r: Report) -> str:
    rows = []
    for app in r.apps:
        cells = defaultdict(list)
        for c in app.copies:
            text = f"{c.version} {c.letter}" + (" · local" if c.local_files else "") + \
                   (" · disabled" if c.disabled else "") + ("" if c.root == "apps" else f" ({c.root})")
            cells[c.server].append(_e(text))
        differs = not app.identical
        sb = ""
        if app.latest:
            link = f'<a href="{_e(app.url)}">{_e(app.latest)}</a>' if app.url else _e(app.latest)
            sb = f'<td class="new">{link} (yeni)</td>' if app.newer_available else f"<td>{link}</td>"
        else:
            sb = "<td></td>"
        name = f'<a href="#app-{_e(app.name)}">{_e(app.name)}</a>' if app.diffs else _e(app.name)
        rows.append(f"<tr><td>{name}</td><td>{_e(KIND_LABEL[app.kind])}</td>"
                    + "".join(f'<td{" class=hi" if differs and cells.get(s) else ""}>{"<br>".join(cells.get(s, []))}</td>'
                              for s in r.server_names) + sb + "</tr>")
    legend = ('<p class="muted">Aynı harf = aynı sürüm ve aynı içerik. “local” = sunucuda local/ değişikliği var. '
              'Sarı satırlarda kopyalar farklı; app adına tıklayınca farklar açılır. '
              'Tür “Splunk” = Splunk ile gelen app (kurulum manifest dosyasından).</p>')
    return "<h2>App'ler</h2>" + legend + _table(["App", "Tür", *r.server_names, "Splunkbase son sürüm"], rows)


def _server_block(app, where: str) -> str | None:
    """The differing settings one copy carries, written the way they look in the conf files."""
    lines, files = [], []
    by_file = defaultdict(lambda: defaultdict(list))
    for d in app.diffs:
        value = d.values.get(where)
        if value in (None, UNSET, NOT_COLLECTED):
            continue
        if d.conf == "dosya":
            files.append(f"{d.stanza}  ({value})")
            continue
        conf_file = "metadata/" + d.layers.get(where, "default") + ".meta" if d.conf == "metadata" \
            else f"{d.layers.get(where, 'default')}/{d.conf}.conf"
        by_file[conf_file][d.stanza].append(f"{d.key} = {value}")
    for conf_file in sorted(by_file):
        lines.append(conf_file)
        for stanza, kvs in by_file[conf_file].items():
            lines.append(f"  [{stanza}]")
            lines += [f"  {kv}" for kv in kvs]
        lines.append("")
    if files:
        lines += ["dosyalar (farklı içerik)"] + [f"  {f}" for f in files]
    if not lines:
        return None
    return f"<div class=srv><b>{_e(where)}</b><pre>{_e(chr(10).join(lines).rstrip())}</pre></div>"


def diffs_section(r: Report) -> str:
    parts = ["<h2>App farkları</h2>",
             '<p class="muted">Her sunucu için yalnızca diğerlerinden farklı olan ayarlar, conf dosyasındaki '
             "haliyle. Splunk'ın kendi yazdığı alanlar (modtime, version, is_configured) gösterilmez.</p>"]
    apps = [a for a in r.apps if a.diffs]
    if not apps:
        return "".join(parts) + "<p>Fark yok.</p>"
    for app in apps:
        notes = "".join(f"<li>{_e(n)}</li>" for n in app.notes)
        blocks, empty, missing = [], [], []
        for c in app.copies:
            if any(d.values.get(c.where) == NOT_COLLECTED for d in app.diffs):
                missing.append(c.where)
                continue
            block = _server_block(app, c.where)
            (blocks.append(block) if block else empty.append(c.where))
        tail = ""
        if empty:
            tail += f'<p class="muted">Bu ayarlar olmadan: {_e(", ".join(empty))}</p>'
        if missing:
            tail += f'<p class="muted">Detay alınamadı: {_e(", ".join(missing))}</p>'
        parts.append(f'<details id="app-{_e(app.name)}"><summary>{_e(app.name)} '
                     f'<span class="muted">({len(app.diffs)} fark)</span></summary>'
                     + (f"<ul>{notes}</ul>" if notes else "") + "".join(blocks) + tail + "</details>")
    return "".join(parts)


def serverclass_section(r: Report) -> str:
    if not r.serverclasses:
        return ""
    parts = ["<h2>serverclass.conf</h2>",
             '<p class="muted">Deployment server’lardaki etkin serverclass.conf (varsayılan dışı satırlar); '
             "her stanza’nın yanında tanımlandığı dosya.</p>"]
    for v in r.serverclasses:
        parts.append(f"<details><summary>{_e(v.server)} <span class=muted>({v.classes} serverclass, "
                     f"{v.apps} app eşlemesi)</span></summary><pre>{_e(v.text)}</pre></details>")
    return "".join(parts)


def system_section(r: Report) -> str:
    parts = ['<h2>Sunucu ayarları (btool)</h2><p class="muted">Varsayılandan farklı ayarlar. '
             'Sarı = sunucular arasında farklı. Hücrenin üzerine gelince kaynağı görünür.</p>']
    by_conf = defaultdict(list)
    for row in r.system:
        by_conf[row.conf].append(row)
    for conf, rows in by_conf.items():
        html_rows = []
        for row in rows:
            cls = " class=hi" if row.differs else ""
            html_rows.append(f"<tr><td>{_e(row.stanza)}</td><td>{_e(row.key)}</td>" + "".join(
                f'<td{cls} title="{_e(row.sources.get(s, "varsayılan"))}">{_e(row.values.get(s, ""))}</td>'
                for s in r.server_names) + "</tr>")
        n_diff = sum(1 for x in rows if x.differs)
        parts.append(f"<details><summary>{_e(conf)}.conf <span class=muted>({len(rows)} ayar, "
                     f"{n_diff} farklı)</span></summary>" + _table(["Stanza", "Key", *r.server_names], html_rows)
                     + "</details>")
    return "".join(parts)


def render(r: Report) -> str:
    return ("<!doctype html><html lang=tr><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            f"<title>Splunk raporu — {_e(r.environment)}</title><style>{CSS}</style><body>"
            f"<h1>Splunk raporu — {_e(r.environment)}</h1><p class=muted>Toplama: {_e(r.run_id)}"
            + (f" · Hariç tutulan app'ler: {_e(', '.join(r.exclude_apps))}" if r.exclude_apps else "") + "</p>"
            + servers_section(r) + os_section(r) + apps_section(r) + diffs_section(r) + serverclass_section(r) + system_section(r) + "</body></html>")
