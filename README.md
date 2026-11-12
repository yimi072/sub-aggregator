# sub-aggregator

Lean v2ray subscription aggregator. Every 2 hours it fetches three public
free-subscription projects that proved to yield usable nodes, merges them
with the owner's own proxies (from `clash.yaml` in the target Gist), dedupes,
and writes the result to `v2ray.txt` in the same Gist — the subscription URL
does not change.

Sources:
- peasoft/NoMoreWalls (full)
- barry-far/V2ray-Config (even sample, cap 250)
- Pawdroid/Free-servers (full)

Dedupe: exact duplicates by endpoint+credential; for raw-IP endpoints the
credential is ignored, so one server listed by several sources under
different names/passwords collapses to a single entry.

Required repository secrets:
- `GIST_LINK` — `username/gist_id` of the target Gist
- `GIST_PAT` — GitHub classic PAT with `gist` scope (set manually)
