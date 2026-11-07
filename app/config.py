"""Runtime configuration, all from environment variables. See .env.example for the full list."""
import os

DATA_DIR = os.environ.get("WAF_DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "waf.db")

BACKFILL_HOURS = int(os.environ.get("WAF_BACKFILL_HOURS", "24"))
RETENTION_HOURS = int(os.environ.get("WAF_RETENTION_HOURS", "72"))
POLL_SECONDS = int(os.environ.get("WAF_POLL_SECONDS", "30"))
AGG_EVERY_SECONDS = int(os.environ.get("WAF_AGG_SECONDS", "60"))
# Re-read this much before the stored watermark so late-arriving Security Lake data is not missed.
BLOCKED_OVERLAP_SECONDS = 600
AGG_OVERLAP_SECONDS = 900
QUERY_TIMEOUT_SECONDS = 150
ATHENA_CONCURRENCY = int(os.environ.get("WAF_ATHENA_CONCURRENCY", "3"))
SEARCH_MAX_HOURS = 24
SEARCH_MAX_ROWS = 2000


def _csv(name, default=""):
    return [p.strip() for p in (os.environ.get(name) or default).split(",") if p.strip()]


# --- AWS access -----------------------------------------------------------------------------
# Credentials come from the standard boto3 chain (env vars, shared config, container/instance
# role, ...). Nothing here is tied to a particular mechanism. Optional knobs:
AWS_PROFILE = os.environ.get("WAF_AWS_PROFILE") or None
# Optional second hop: assume this role (for example a role in the Security Lake account) using
# whatever credentials the chain produced.
ASSUME_ROLE_ARN = os.environ.get("WAF_ASSUME_ROLE_ARN") or None
ASSUME_ROLE_EXTERNAL_ID = os.environ.get("WAF_ASSUME_ROLE_EXTERNAL_ID") or None
ASSUME_ROLE_SESSION = os.environ.get("WAF_ASSUME_ROLE_SESSION") or "waf-dashboard"

# --- Athena -----------------------------------------------------------------------------------
WORKGROUP = os.environ.get("WAF_ATHENA_WORKGROUP") or "primary"
# Results location. "{region}" is replaced per region. Leave empty if the workgroup enforces one.
OUTPUT_LOCATION = os.environ.get("WAF_ATHENA_OUTPUT") or ""

# --- Security Lake ----------------------------------------------------------------------------
# One entry per Security Lake region to read. Database and table names follow the Security Lake
# convention and can be overridden with templates ({region_u} = region with underscores).
REGIONS = _csv("WAF_REGIONS", "us-east-1")
SL_DB_TEMPLATE = os.environ.get("WAF_SL_DB_TEMPLATE") or "amazon_security_lake_glue_db_{region_u}"
SL_TABLE_TEMPLATE = os.environ.get("WAF_SL_TABLE_TEMPLATE") or "amazon_security_lake_table_{region_u}_waf_2_0"

SOURCES = {
    r: {"db": SL_DB_TEMPLATE.format(region_u=r.replace("-", "_"), region=r),
        "table": SL_TABLE_TEMPLATE.format(region_u=r.replace("-", "_"), region=r)}
    for r in REGIONS
}

# --- Rule display -----------------------------------------------------------------------------
# Prefixes removed from rule names for display only (for example your own naming convention).
RULE_STRIP_PREFIXES = _csv("WAF_RULE_STRIP_PREFIXES")

# Optional account id -> friendly name map (JSON object). See accounts.example.json.
ACCOUNTS_FILE = os.environ.get("WAF_ACCOUNTS_FILE") or ""

# --- Source IP ownership ----------------------------------------------------------------------
# "public" uses Team Cymru, RDAP and RADb (the IPs being looked up are sent to those services).
# "off" disables lookups entirely.
WHOIS_MODE = (os.environ.get("WAF_WHOIS") or "public").lower()

# --- HTTP exposure ----------------------------------------------------------------------------
# Host header allow-list (DNS-rebinding protection). Entries: exact names, "*.example.com", or "*" to disable.
# Add the name or address users type in the browser when exposing the dashboard beyond loopback.
ALLOWED_HOSTS = [h.lower() for h in _csv("WAF_ALLOWED_HOSTS", "localhost,127.0.0.1,::1")]
# Optional "user:password" gate. Validated at startup; a malformed value stops the app instead of running open.
BASIC_AUTH = os.environ.get("WAF_BASIC_AUTH") or ""
BASIC_AUTH_MIN_PASSWORD = 12
AUTH_FAIL_LIMIT = 10          # failed attempts per client ...
AUTH_FAIL_WINDOW_SECONDS = 300  # ... within this window before the client gets 429
MAX_STREAMS = int(os.environ.get("WAF_MAX_STREAMS") or "50")
API_QUERY_TIMEOUT_SECONDS = float(os.environ.get("WAF_API_QUERY_TIMEOUT") or "15")

# --- Deep Search limits (Athena cost controls) --------------------------------------------------
SEARCH_PER_CLIENT_HOUR = int(os.environ.get("WAF_SEARCH_PER_CLIENT_HOUR") or "30")
SEARCH_GLOBAL_HOUR = int(os.environ.get("WAF_SEARCH_GLOBAL_HOUR") or "120")
SEARCH_MAX_RUNNING = 4
# Stop accepting searches once this much has been scanned today (UTC). 0 = no budget.
SEARCH_DAILY_SCAN_GB = float(os.environ.get("WAF_SEARCH_DAILY_SCAN_GB") or "0")
