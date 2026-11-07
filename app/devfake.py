"""Synthetic demo data for trying the UI without AWS. Enabled only with WAF_DEV_FAKE=1."""
import asyncio
import random
import time

import store
from engine import now_ms

RULES = [
    ("restrict-to-allowed-networks", "REGULAR", None, 30),
    ("AWS-AWSManagedRulesAmazonIpReputationList", "MANAGED_RULE_GROUP", "AWSManagedIPReputationList", 22),
    ("AWS-AWSManagedRulesKnownBadInputsRuleSet", "MANAGED_RULE_GROUP", "ExploitablePaths_URIPATH", 14),
    ("AWS-AWSManagedRulesCommonRuleSet", "MANAGED_RULE_GROUP", "GenericLFI_BODY", 8),
    ("AWS-AWSManagedRulesCommonRuleSet", "MANAGED_RULE_GROUP", "UserAgent_BadBots_HEADER", 6),
    ("enforce-allowlist", "REGULAR", None, 8),
    ("geo-block-list", "REGULAR", None, 5),
    ("rate-limit-login", "RATE_BASED", None, 7),
]
# Fictional accounts and hosts (reserved example.com domains, documentation-only IP ranges).
HOSTS = [("111111111111", "web-storefront-prod", "shop.example.com", "storefront-alb-prod"),
         ("222222222222", "api-gateway-prod", "api.example.com", "api-alb-prod"),
         ("333333333333", "analytics-dev", "analytics.example.net", "analytics-alb-dev")]
PATHS = ["/", "/admin/login.js", "/wp-login.php", "/.env", "/api/v1/items", "/../../etc/passwd", "/robots.txt", "/actuator/health"]
UAS = ["Mozilla/5.0 zgrab/0.x", "curl/8.4.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "python-requests/2.31", "Go-http-client/1.1"]
store.ACCOUNT_NAMES.update({h[0]: h[1] for h in HOSTS})
COUNTRIES = ["US", "RU", "CN", "SC", "NL", "BR", "DE", "IN"]
NETS = ["192.0.2", "198.51.100", "203.0.113"]


def make(ts):
    rule, rtype, inner, _ = random.choices(RULES, weights=[r[3] for r in RULES])[0]
    acct, name, host, res = random.choice(HOSTS)
    raw = {
        "ts": str(ts), "account": acct, "region": "us-east-1", "ip": f"{random.choice(NETS)}.{random.randint(1, 254)}",
        "country": random.choices(COUNTRIES, weights=[3, 4, 4, 2, 1, 1, 1, 1])[0],
        "resource": f"{acct}-app/{res}/{random.getrandbits(64):016x}", "svc": "ALB", "host": host, "path": random.choice(PATHS),
        "args": random.choice([None, "id=1' OR '1'='1", "q=<script>alert(1)</script>"]),
        "method": random.choices(["GET", "POST", "HEAD"], weights=[8, 3, 1])[0], "ua": random.choice(UAS),
        "req_id": f"1-{random.getrandbits(32):08x}-{random.getrandbits(96):024x}", "referrer": None, "xff": None,
        "status": random.choice([None, "403"]), "rule": rule, "rule_type": rtype,
        "cond": random.choice([None, "REGEX", "CONTAINS"]), "match_loc": random.choice([None, "HEADER", "URI_PATH"]),
        "match_det": None, "rate_limit": None, "inner_rule": inner, "term_action": "BLOCK",
        "evaluated_groups": "AWS#" + rule[4:] if rule.startswith("AWS-") else None, "matched_field": None, "nonterm_rules": None,
        "ja3": f"{random.getrandbits(128):032x}", "ja4": "t13d000000_000000000000_000000000000",
        "labels": '{"name":"awswaf:clientip:geo:country:US"}',
    }
    return store.enrich(raw, "us-east-1")


def seed(hours=24):
    now = now_ms()
    evs = [make(now - random.randint(0, hours * 3600 * 1000)) for _ in range(hours * 900)]
    store.insert_events(evs)
    orgs = [("AMAZON-02", "AS16509"), ("GOOGLE", "AS15169"), ("DIGITALOCEAN-ASN", "AS14061"), ("CHINANET-BACKBONE", "AS4134"),
            ("MICROSOFT-CORP-MSN-AS-BLOCK", "AS8075"), ("Censys, Inc.", "AS398705"), ("OVH SAS", "AS16276"), ("Hurricane Electric LLC", "AS6939")]
    recs = {}
    for e in evs:
        if e["ip"] not in recs:
            o = random.choice(orgs)
            recs[e["ip"]] = {"org": o[0], "asn": o[1], "net_name": o[0].split()[0] + "-NET", "geo_country": e["country"],
                             "geo_city": None, "via": "cymru"}
    store.save_ip_info(recs)
    base = now // 60000 * 60 - hours * 3600
    rows = []
    for m in range(hours * 60):
        for acct, _, host, _ in HOSTS:
            rows.append({"minute": base + m * 60, "account": acct, "host": host, "disp": "Allowed",
                         "n": random.randint(3000, 9000)})
    store.replace_agg("us-east-1", base, base + hours * 3600 + 60, rows)


async def live(engine):
    while True:
        await asyncio.sleep(random.uniform(1.5, 4))
        new = store.insert_events([make(now_ms()) for _ in range(random.randint(1, 4))])
        engine.publish({"type": "blocked", "count": len(new), "rows": new})
