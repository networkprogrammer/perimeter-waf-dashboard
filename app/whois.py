"""Source IP ownership lookup using only public sources.

Order per IP: Team Cymru (ASN) -> RDAP -> RADb. Private and reserved addresses are labelled locally and
never leave the host. Set WAF_WHOIS=off to disable lookups entirely.
"""
import ipaddress
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
import urllib.request

import config

ENABLED = config.WHOIS_MODE == "public"


def classify(ip):
    """Returns a label for non-public addresses, else None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid address"
    if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:
        return "Private / reserved address"
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return "Private / reserved address"
    return None


def _whois43(server, query, timeout=5):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        chunks, total = [], 0
        while total < 100_000:
            b = s.recv(8192)
            if not b:
                break
            chunks.append(b)
            total += len(b)
    return b"".join(chunks).decode("utf-8", "replace")


def _cymru(ip):
    try:
        txt = _whois43("whois.cymru.com", f" -v {ip}")
    except Exception:  # noqa: BLE001
        return None
    for line in txt.splitlines():
        p = [x.strip() for x in line.split("|")]
        if len(p) >= 7 and p[0].isdigit():
            name = re.sub(r",\s*[A-Z]{2}$", "", p[6]) or None
            return {"asn": "AS" + p[0], "org": name, "geo_country": p[3] or None, "via": "cymru"}
    return None


def _rdap(ip):
    for url in (f"https://rdap.org/ip/{ip}", f"https://rdap.arin.net/registry/ip/{ip}"):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/rdap+json", "User-Agent": "waf-dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                d = json.loads(r.read(300_000).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            continue
        org = None
        for e in d.get("entities", []) or []:
            for item in (e.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    org = org or item[3]
        return {"net_name": d.get("name"), "org": org, "geo_country": d.get("country"), "via": "rdap"}
    return None


def _radb(ip):
    try:
        txt = _whois43("whois.radb.net", ip)
    except Exception:  # noqa: BLE001
        return None
    origin = descr = None
    for line in txt.splitlines():
        if line.startswith("origin:") and not origin:
            origin = line.split(":", 1)[1].strip()
        elif line.startswith("descr:") and not descr:
            descr = line.split(":", 1)[1].strip()
    return {"asn": origin, "org": descr, "via": "radb"} if (origin or descr) else None


def lookup_one(ip):
    """Resolve one public IP via the public sources. Always returns a dict."""
    rec = {"org": None, "net_name": None, "asn": None, "geo_country": None, "geo_city": None, "via": "none"}

    def merge(src):
        if not src:
            return
        for k, v in src.items():
            if k != "via" and v and not rec.get(k):
                rec[k] = v
        if rec["via"] == "none":
            rec["via"] = src["via"]

    merge(_cymru(ip))
    if not rec["org"]:
        merge(_rdap(ip))
    if not rec["org"]:
        merge(_radb(ip))
    return rec


def lookup_many(ips):
    """Returns {ip: record}. Non-public addresses are labelled locally; public ones use the public sources."""
    res, todo = {}, []
    for ip in ips:
        label = classify(ip)
        if label:
            res[ip] = {"org": label, "net_name": None, "asn": None, "geo_country": None, "geo_city": None, "via": "local"}
        else:
            todo.append(ip)
    if todo and ENABLED:
        with ThreadPoolExecutor(max_workers=12) as ex:
            for ip, rec in zip(todo, ex.map(lookup_one, todo)):
                res[ip] = rec
    else:
        for ip in todo:
            res[ip] = {"org": None, "net_name": None, "asn": None, "geo_country": None, "geo_city": None, "via": "none"}
    return res
