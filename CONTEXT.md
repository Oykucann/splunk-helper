# splunk-helper — domain language

**Environment**: One customer Splunk estate (one or two sites) that will be consolidated
into a multisite indexer cluster with a search head cluster.

**Site**: A physical/logical location (`site1`, `site2`). Today sites are independent;
content may be the same or different between them.

**Server**: One Splunk instance with a role: `sh`, `cm`, `ds`, `deployer`, `hf`, `idx`.
A lab instance may carry extra roles (`also_roles`, e.g. SH that is also the CM); it is collected
once, rules see every role, comparisons group it under its primary `role`.

**HA Group**: Heavy forwarders that serve the same push inputs behind one VIP —
a keepalived pair, or N HFs behind haproxy. All members must be configured identically.

**Pull HF**: A dedicated heavy forwarder running pull inputs. Not part of an HA group.

**Co-located pull role**: An HA-group member that also runs pull inputs on its own address
(not the VIP), declared with `pull_apps`. Unaffected by VIP moves; no failover if the node is down.

**Push Input**: Data sent to Splunk: syslog (udp/tcp), HEC, splunktcp (UF → HF).
Must be identical on every member of an HA group.

**Pull Input**: Data fetched by Splunk: DB Connect, scripted, API modular inputs.
Must run on exactly one server (a Pull HF), never on an HA group.

**VIP**: Virtual IP owned by keepalived or haproxy. Never a collection target.

**Snapshot**: The read-only, redacted capture of one server, produced by the remote
collector as a `.tar.gz` stream. Immutable once written.

**Run**: One collection pass over an Environment. Has an ID; produces one snapshot per server.

**Drift**: Difference between what the deployment server intends (`serverclass.conf`,
`deployment-apps`) and what is actually installed on a client.

**Finding**: A problem backed by evidence (file + stanza + key, or search result).
Has severity and confidence (`proven` / `suspected`).

**Risk class** (of a proposed change): 🟢 safe, 🟡 risky, 🔴 dangerous (never generated).
