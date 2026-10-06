# ADR-0001: Read-only collection

## Status

Accepted (2026-10-06)

## Context

Target environments are production. All data flows through heavy forwarders; most HFs run
as keepalived pairs whose failover decision probes splunkd's management port (8089).
DS-managed HFs, DB Connect checkpoints and listening ports make any accidental change
expensive. We need discovery data within one week, without a separate hardening project.

## Decision

1. **File-level data via SSH, streamed script.** `collect_remote.py` is piped to
   `splunk cmd python3 -` over the operator's existing SSH access, as the splunk user.
   Nothing is installed or written on the target. Output is a `tar.gz` on stdout.
2. **The remote script is read-only by construction.** It may only read files, stat paths
   and run `splunk btool <conf> list --debug`. A test parses its AST and fails on any
   write-mode `open`, filesystem mutation, or subprocess call outside `_run_btool`.
3. **Redaction happens on the target.** Secret-looking values and any `$7$`/`$1$` encrypted
   value are replaced with a salted fingerprint. The salt lives only in the driver's memory
   for the run, so equal secrets can be compared across servers but not brute-forced later.
   Lookup files and script bodies are never copied; only metadata and suspected-secret line
   numbers.
4. **No REST on heavy forwarders.** Runtime facts about HFs come from `_internal` searches
   on the search head (later slice). REST is used only against the SH, with a read-only role.
5. **No VIPs; sequential.** The driver refuses targets listed as VIPs and collects one
   server at a time, at lowest CPU priority, with a timeout.

## Consequences

- The guarantee in week 1 rests on review of one short script plus the AST test, not on a
  restricted account. Week 2 should move to an `authorized_keys` forced-command user.
- Effective configuration is taken from btool output; we do not re-implement precedence.
  App/user-context-specific search-time behaviour is out of scope and reported as such.

## Alternatives considered

- REST-only collection: cannot see `local/` vs `default/`, staged `deployment-apps` /
  `manager-apps` / `shcluster/apps`, scripts or `splunk.secret`. Also loads splunkd on HFs.
- Agent installed on servers: requires change approval; writes to prod.
