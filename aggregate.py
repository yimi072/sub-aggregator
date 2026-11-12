#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate a lean v2ray subscription into an existing GitHub Gist.

Sources (only projects verified to yield usable nodes):
  - peasoft/NoMoreWalls        (full)
  - barry-far/V2ray-Config     (even sample, capped)
  - Pawdroid/Free-servers      (full)
Plus the owner's own proxies, read from clash.yaml in the same Gist
(produced earlier by the aggregator fork; kept as-is).

Dedupe: exact duplicates are dropped by endpoint+credential; for raw-IP
endpoints the credential is ignored, so the same server re-listed by
several sources under different names/passwords collapses to one entry.

Workflow mode (default): needs env GIST_PAT and GIST_LINK (user/gist_id);
writes the merged, base64-encoded list to v2ray.txt in that Gist.
Offline mode: --clash-file X --out Y [--src-file name=path ...]
Only the Python standard library plus PyYAML are used.
"""

import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request

import yaml

API = "https://api.github.com"


def b64url_nopad(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def q(text) -> str:
    return urllib.parse.quote(str(text), safe="")


def conv_ss(p):
    userinfo = b64url_nopad(f"{p.get('cipher')}:{p.get('password')}")
    link = f"ss://{userinfo}@{p.get('server')}:{p.get('port')}"
    plugin = p.get("plugin")
    if plugin:
        opts = p.get("plugin-opts") or {}
        parts = [str(plugin)]
        for k, v in opts.items():
            parts.append(f"{k}={v}")
        link += "?plugin=" + q(";".join(parts))
    return link + "#" + q(p.get("name", ""))


def conv_hysteria2(p):
    params = {}
    sni = p.get("sni") or p.get("servername")
    if sni:
        params["sni"] = sni
    if p.get("skip-cert-verify"):
        params["insecure"] = "1"
    if p.get("obfs"):
        params["obfs"] = p["obfs"]
        if p.get("obfs-password"):
            params["obfs-password"] = p["obfs-password"]
    if p.get("alpn"):
        alpn = p["alpn"]
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    if p.get("ports"):
        params["mport"] = str(p["ports"]).replace(",", "-")
    query = urllib.parse.urlencode(params)
    auth = q(p.get("password", ""))
    link = f"hysteria2://{auth}@{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


def conv_hysteria(p):
    params = {}
    auth = p.get("auth-str") or p.get("auth_str") or p.get("password", "")
    if auth:
        params["auth"] = auth
    sni = p.get("sni") or p.get("peer") or p.get("servername")
    if sni:
        params["peer"] = sni
    if p.get("skip-cert-verify"):
        params["insecure"] = "1"
    if p.get("alpn"):
        alpn = p["alpn"]
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    if p.get("up"):
        params["upmbps"] = p["up"]
    if p.get("down"):
        params["downmbps"] = p["down"]
    query = urllib.parse.urlencode(params)
    link = f"hysteria://{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


def conv_vmess(p):
    data = {
        "v": "2",
        "ps": str(p.get("name", "")),
        "add": str(p.get("server", "")),
        "port": str(p.get("port", "")),
        "id": str(p.get("uuid", "")),
        "aid": str(p.get("alterId", 0)),
        "scy": str(p.get("cipher", "auto")),
        "net": str(p.get("network", "tcp")),
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if p.get("tls") else "",
        "sni": str(p.get("servername") or p.get("sni") or ""),
    }
    ws = p.get("ws-opts") or {}
    if ws:
        headers = ws.get("headers") or {}
        if headers.get("Host"):
            data["host"] = str(headers["Host"])
        if ws.get("path"):
            data["path"] = str(ws["path"])
    grpc = p.get("grpc-opts") or {}
    if grpc.get("grpc-service-name"):
        data["path"] = str(grpc["grpc-service-name"])
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode()).decode()


def conv_trojan(p):
    params = {}
    sni = p.get("sni") or p.get("servername")
    if sni:
        params["sni"] = sni
    if p.get("skip-cert-verify"):
        params["allowInsecure"] = "1"
    if p.get("network"):
        params["type"] = p["network"]
    ws = p.get("ws-opts") or {}
    if ws.get("path"):
        params["path"] = ws["path"]
    headers = ws.get("headers") or {}
    if headers.get("Host"):
        params["host"] = headers["Host"]
    query = urllib.parse.urlencode(params)
    link = f"trojan://{q(p.get('password', ''))}@{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


def conv_vless(p):
    params = {"encryption": "none"}
    if p.get("tls"):
        params["security"] = "reality" if p.get("reality-opts") else "tls"
    else:
        params["security"] = "none"
    sni = p.get("servername") or p.get("sni")
    if sni:
        params["sni"] = sni
    if p.get("flow"):
        params["flow"] = p["flow"]
    params["type"] = p.get("network", "tcp")
    ro = p.get("reality-opts") or {}
    if ro.get("public-key"):
        params["pbk"] = ro["public-key"]
    if ro.get("short-id"):
        params["sid"] = ro["short-id"]
    ws = p.get("ws-opts") or {}
    if ws.get("path"):
        params["path"] = ws["path"]
    headers = ws.get("headers") or {}
    if headers.get("Host"):
        params["host"] = headers["Host"]
    grpc = p.get("grpc-opts") or {}
    if grpc.get("grpc-service-name"):
        params["serviceName"] = grpc["grpc-service-name"]
    query = urllib.parse.urlencode(params)
    return (
        f"vless://{p.get('uuid')}@{p.get('server')}:{p.get('port')}?{query}"
        f"#{q(p.get('name', ''))}"
    )


def conv_tuic(p):
    params = {}
    sni = p.get("sni") or p.get("servername")
    if sni:
        params["sni"] = sni
    if p.get("alpn"):
        alpn = p["alpn"]
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    if p.get("congestion-controller"):
        params["congestion_control"] = p["congestion-controller"]
    if p.get("skip-cert-verify"):
        params["allow_insecure"] = "1"
    query = urllib.parse.urlencode(params)
    link = f"tuic://{q(p.get('uuid', ''))}:{q(p.get('password', ''))}@{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


CONVERTERS = {
    "ss": conv_ss,
    "hysteria2": conv_hysteria2,
    "hy2": conv_hysteria2,
    "hysteria": conv_hysteria,
    "vmess": conv_vmess,
    "trojan": conv_trojan,
    "vless": conv_vless,
    "tuic": conv_tuic,
}


def convert_proxies(proxies):
    links, skipped = [], {}
    for p in proxies or []:
        if not isinstance(p, dict):
            continue
        ptype = str(p.get("type", "")).lower()
        fn = CONVERTERS.get(ptype)
        if fn is None:
            skipped[ptype] = skipped.get(ptype, 0) + 1
            continue
        try:
            links.append(fn(p))
        except Exception:
            skipped[ptype] = skipped.get(ptype, 0) + 1
    return links, skipped


# Extra public free-subscription projects merged into v2ray.txt.
# (name, raw url, cap; cap=0 means take everything parseable)
EXTRA_SOURCES = [
    ("nomorewalls", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 0),
    ("barry-far", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_base64_Sub.txt", 250),
    ("pawdroid", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", 0),
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
    req.add_header("User-Agent", "clash2v2ray/1.0")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf8", errors="replace")


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
            for ln in picked:
                key = link_key(ln)
                if key in seen:
                    continue
                seen.add(key)
                extras.append(ln)
                added += 1
            print(
                f"extra[{name}]: parsed={len(links)} picked={len(picked)} added={added}",
                flush=True,
            )
        except Exception as e:
            print(f"extra[{name}] failed: {e}", flush=True)
    return extras


def links_from_clash(clash_text: str):
    data = yaml.safe_load(clash_text) or {}
    proxies = data.get("proxies") or []
    links, skipped = convert_proxies(proxies)
    counts = {}
    for link in links:
        scheme = link.split("://", 1)[0]
        counts[scheme] = counts.get(scheme, 0) + 1
    print(
        f"proxies={len(proxies)} links={len(links)} by_scheme={counts} skipped={skipped}",
        flush=True,
    )
    if not links:
        raise SystemExit("no convertible proxies found, refusing to overwrite v2ray.txt")
    return links


def build_v2ray_content(clash_text: str, extra_links=None) -> str:
    links = links_from_clash(clash_text)
    if extra_links:
        links = links + list(extra_links)
        print(f"total links with extras: {len(links)}", flush=True)
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
    if "--input" in argv or "--clash-file" in argv:
        i = argv.index("--input") if "--input" in argv else argv.index("--clash-file")
        o = argv.index("--output") if "--output" in argv else argv.index("--out")
        local_files = {}
        for j, arg in enumerate(argv):
            if arg in ("--extra-file", "--src-file") and j + 1 < len(argv) and "=" in argv[j + 1]:
                nm, path = argv[j + 1].split("=", 1)
                local_files[nm] = path
        with open(argv[i + 1], encoding="utf8") as f:
            clash_text = f.read()
        own = links_from_clash(clash_text)
        extras = collect_extra_links(own, local_files=local_files or None)
        content = build_v2ray_content(clash_text, extra_links=extras)
        with open(argv[o + 1], "w", encoding="utf8") as f:
            f.write(content)
        print(f"wrote {argv[o + 1]}")
        return 0

    token = os.environ.get("GIST_PAT", "").strip()
    link = os.environ.get("GIST_LINK", "").strip()
    if not token or "/" not in link:
        raise SystemExit("GIST_PAT and GIST_LINK (user/gist_id) are required")
    gist_id = link.split("/", 1)[1].strip()

    gist = http("GET", f"{API}/gists/{gist_id}", token)
    files = gist.get("files") or {}
    clash_file = files.get("clash.yaml")
    if not clash_file:
        raise SystemExit("clash.yaml not found in gist, collect may have failed")

    clash_text = clash_file.get("content") or ""
    if clash_file.get("truncated") or not clash_text:
        raw_url = clash_file.get("raw_url")
        req = urllib.request.Request(raw_url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            clash_text = resp.read().decode()

    own = links_from_clash(clash_text)
    extras = []
    if os.environ.get("EXTRA_SUBS", "").strip().lower() != "off":
        extras = collect_extra_links(own)
    content = build_v2ray_content(clash_text, extra_links=extras)
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
