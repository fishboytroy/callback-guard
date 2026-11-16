# Architecture and editions

This repository is the **free Community engine** of Callback Guard. It is
source-available under the Business Source License 1.1 (see [LICENSE](LICENSE)
and [LICENSING.md](LICENSING.md)). It is complete and fully functional on its
own: nothing here is crippled or time-limited.

Paid **Pro / Business** value is delivered as a separate, privately distributed
layer that is **never committed to this public repository**. This document
describes the boundary between the two so the split stays clean from day one.

## What lives where

| Layer | Where it lives | License |
| --- | --- | --- |
| Scanning engine, desktop UI, APK triage, monitor, benchmark, corpus | This public repo | BSL 1.1 (source-available) |
| Pro/Business features (team policy, managed update feed, dashboards, entitlement, support tooling) | A private repo / privately distributed module | Commercial, not published |

Because the paid layer is never published, a copy of this public repository
gets someone only the free tier — which is given away anyway. The moat is the
layer that is not in this repo, not the engine that is.

## The extension point

The engine exposes exactly one optional hook, `apply_pro_extensions()` in
[`guard.py`](guard.py). During a scan, immediately after the findings list is
finalized (and any opt-in OSV enrichment), the engine attempts:

```python
import callback_guard_pro        # absent in the free tier
added = callback_guard_pro.enrich(report_snapshot, data, name)
```

- `callback_guard_pro` is **not shipped here** and is git-ignored
  (`callback_guard_pro.py`, `callback_guard_pro/`, `pro/`). If it is not
  installed, the import fails quietly and the scan is unaffected.
- `enrich(report_snapshot, data, name)` receives a **deep copy** of the report,
  the raw bytes, and the filename. It returns a list of additional finding
  dicts to append (or nothing).
- The engine then recomputes the blocking decision, max severity, risk summary,
  and the release gate from the **combined** findings.

### Security invariant (non-negotiable)

The paid layer may **only add** findings and a `report["pro"]` status section.
It can never clear, downgrade, or bypass a result:

- It is handed a deep copy, so it cannot mutate or delete the engine's own
  findings.
- The blocking/release decision is recomputed by the engine *after* the hook,
  from the full findings list — so a Pro finding can **hold** a scan but a Pro
  module can never turn a held scan into `checks-passed`.
- Any exception in the extension is caught and recorded as
  `report["pro"] = {"status": "error", ...}`; a broken or hostile extension
  cannot break or weaken the free scan.

This mirrors the rule already stated in `SKILL.md` for the injection review:
reviews and enrichments may add, never override a hold.

## Building a Pro module

A Pro module is any importable `callback_guard_pro` exposing:

```python
__version__ = "1.0.0"

def enrich(report, data, name):
    """Return a list of extra finding dicts (same shape as engine findings:
    at least 'rule' and 'severity'). Must not rely on mutating `report`."""
    return [...]
```

Install it next to `guard.py` (or anywhere on `sys.path`) only on machines
entitled to the paid tier. Keep its source in a private repository; this public
repo intentionally has no way to contain it.
