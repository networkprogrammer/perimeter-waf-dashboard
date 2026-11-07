"""Capture screenshots from demo mode (synthetic data, no AWS). Output has the same layout as the README images
but a smaller synthetic data set.

Usage:
  cd app && WAF_DEV_FAKE=1 WAF_DATA_DIR=/tmp/wafdemo uvicorn main:app --port 8080 &
  pip install playwright && playwright install chromium     # or use an installed Chrome via channel="chrome"
  python scripts/screenshots.py http://127.0.0.1:8080 docs/screenshots
"""
import os
import sys

from playwright.sync_api import sync_playwright

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
out = sys.argv[2] if len(sys.argv) > 2 else "docs/screenshots"
os.makedirs(out, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1680, "height": 1050}, timezone_id="UTC", locale="en-US")
    page = ctx.new_page()
    page.goto(base + "/#range=24h")
    page.wait_for_timeout(3500)
    page.screenshot(path=os.path.join(out, "dashboard.png"))
    page.screenshot(path=os.path.join(out, "dashboard-full.png"), full_page=True)
    page.evaluate("window.scrollTo(0, 760)")
    page.locator("table tbody tr").nth(1).locator("td").first.click()
    page.wait_for_timeout(1500)
    page.screenshot(path=os.path.join(out, "row-detail.png"))
    browser.close()
