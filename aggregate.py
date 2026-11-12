#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate a lean v2ray subscription into an existing GitHub Gist.

Sources (only projects verified to yield usable nodes):
  - peasoft/NoMoreWalls        (full)
  - barry-far/V2ray-Config     (even sample, capped)

Junk filter: nodes pointing at loopback / private / localhost addresses
(planted fake entries such as 127.0.0.53) are dropped.
Dedupe: exact duplicates are dropped by endpoint+credential; for raw-IP
endpoints the credential is ignored, so the same server re-listed by
several sources under different names/passwords collapses to one entry.

Workflow mode (default): needs env GIST_PAT and GIST_LINK (user/gist_id);
writes the merged, base64-encoded list to v2ray.txt in that Gist.
Offline mode: --out Y [--src-file name=path ...]
Only the Python standard library plus PyYAML are used.
"""

import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request


API = "https://api.github.com"


def b64url_nopad(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def q(text) -> str:
    return urllib.parse.quote(str(text), safe="")


# Extra public free-subscription projects merged into v2ray.txt.
# (name, raw url, cap; cap=0 means take everything parseable)
EXTRA_SOURCES = [
    ("nomorewalls", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 0),
    ("barry-far", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_base64_Sub.txt", 250),
]

ALLOWED_SCHEMES = {"ss", "vmess", "trojan", "vless", "hysteria2", "hy2", "tuic"}


def parse_subscription(text: str):
    lines = [ln.strip() for ln in text.splitlines() if "://" in ln]
    valid = [ln for ln in lines if ln.split("://", 1)[0].lower() in ALLOWED_SCHEMES]
    if len(valid) >= 3:
        return valid
    compact = re.sub(r"\s+", "", text)
    if not compact:
        return []
    for alt in (None, b"-_"):
        try:
            dec = base64.b64decode(
                compact + "=" * (-len(compact) % 4), altchars=alt
            ).decode("utf8")
        except Exception:
            continue
        lines = [ln.strip() for ln in dec.splitlines() if "://" in ln]
        return [ln for ln in lines if ln.split("://", 1)[0].lower() in ALLOWED_SCHEMES]
    return []


IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def link_key(link: str):
    """Dedupe key. Raw-IP endpoint: one entry per scheme+host+port
    (same server re-listed under other names/passwords collapses).
    Domain endpoint: credential stays in the key (shared CDN fronts)."""
    try:
        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:].split("#", 1)[0]))
            host = str(data.get("add", "")).lower()
            port = str(data.get("port", ""))
            if IP_RE.match(host):
                return ("vmess", host, port)
            return ("vmess", host, port, data.get("id", ""))
        u = urllib.parse.urlparse(link)
        scheme = u.scheme.lower()
        if scheme == "hy2":
            scheme = "hysteria2"
        host = (u.hostname or "").lower()
        port = u.port
        if IP_RE.match(host) or ":" in host:
            return (scheme, host, port)
        cred = urllib.parse.unquote(u.username or "")
        if u.password:
            cred += ":" + urllib.parse.unquote(u.password)
        return (scheme, host, port, cred)
    except Exception:
        return ("raw", link.split("#", 1)[0])


def sample_evenly(items, cap):
    if cap <= 0 or len(items) <= cap:
        return items
    n = len(items)
    return [items[int(i * n / cap)] for i in range(cap)]


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "sub-aggregator/1.0")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf8", errors="replace")


JUNK_HOST_RE = re.compile(
    r"^(localhost|0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|::1)$"
)


def link_host(link: str) -> str:
    try:
        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:].split("#", 1)[0]))
            return str(data.get("add", "")).lower()
        return (urllib.parse.urlparse(link).hostname or "").lower()
    except Exception:
        return ""


def is_junk(link: str) -> bool:
    host = link_host(link)
    return bool(host) and bool(JUNK_HOST_RE.match(host))


def collect_extra_links(own_links, local_files=None):
    seen = {link_key(ln) for ln in own_links}
    extras = []
    for name, url, cap in EXTRA_SOURCES:
        try:
            if local_files and name in local_files:
                with open(local_files[name], encoding="utf8", errors="replace") as f:
                    text = f.read()
            else:
                text = fetch_text(url)
            links = parse_subscription(text)
            picked = sample_evenly(links, cap)
            added = 0
            junk = 0
            for ln in picked:
                if is_junk(ln):
                    junk += 1
                    continue
                key = link_key(ln)
                if key in seen:
                    continue
                seen.add(key)
                extras.append(ln)
                added += 1
            print(
                f"extra[{name}]: parsed={len(links)} picked={len(picked)} added={added} junk_dropped={junk}",
                flush=True,
            )
        except Exception as e:
            print(f"extra[{name}] failed: {e}", flush=True)
    return extras


def build_content(links) -> str:
    if not links:
        raise SystemExit("no links collected, refusing to overwrite v2ray.txt")
    counts = {}
    for link in links:
        scheme = link.split("://", 1)[0]
        counts[scheme] = counts.get(scheme, 0) + 1
    print(f"total links: {len(links)} by_scheme={counts}", flush=True)
    body = "\n".join(links)
    return base64.b64encode(body.encode()).decode()


def http(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
        return json.loads(raw.decode()) if raw.strip() else {}


def main(argv):
    # offline mode: aggregate.py --out FILE [--src-file name=path ...]
    if "--out" in argv or "--output" in argv:
        o = argv.index("--out") if "--out" in argv else argv.index("--output")
        local_files = {}
        for j, arg in enumerate(argv):
            if arg in ("--src-file", "--extra-file") and j + 1 < len(argv) and "=" in argv[j + 1]:
                nm, path = argv[j + 1].split("=", 1)
                local_files[nm] = path
        links = collect_extra_links([], local_files=local_files or None)
        content = build_content(links)
        with open(argv[o + 1], "w", encoding="utf8") as f:
            f.write(content)
        print(f"wrote {argv[o + 1]}")
        return 0

    token = os.environ.get("GIST_PAT", "").strip()
    link = os.environ.get("GIST_LINK", "").strip()
    if not token or "/" not in link:
        raise SystemExit("GIST_PAT and GIST_LINK (user/gist_id) are required")
    gist_id = link.split("/", 1)[1].strip()

    links = collect_extra_links([])
    content = build_content(links)
    http(
        "PATCH",
        f"{API}/gists/{gist_id}",
        token,
        body={"files": {"v2ray.txt": {"content": content, "filename": "v2ray.txt"}}},
    )
    print("v2ray.txt updated in gist")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
