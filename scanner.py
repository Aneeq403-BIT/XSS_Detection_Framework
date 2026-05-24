import urllib.parse
import html
import base64
import re
from playwright.async_api import async_playwright

class EnterpriseScanner:
    def __init__(self):
        # Deterministic Rule Engine for immediate blocking (saves AI compute)
        self.basic_signatures = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe"
        ]

    def recursive_decode(self, payload, depth=0, max_depth=4):
        """Recursively decodes nested obfuscation (URL -> HTML -> Base64)"""
        if depth >= max_depth or not isinstance(payload, str):
            return payload.lower()

        original_payload = payload
        payload = urllib.parse.unquote(payload) # 1. URL Decode
        payload = html.unescape(payload)        # 2. HTML Entity Decode
        
        # 3. Base64 Decode Attempt
        try:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', payload) and len(payload) > 10:
                payload = base64.b64decode(payload).decode('utf-8')
        except Exception:
            pass

        # If payload was unwrapped, recurse to check for deeper layers
        if payload != original_payload:
            return self.recursive_decode(payload, depth + 1, max_depth)
        
        return payload.lower()

    def rule_engine_scan(self, payload):
        """Fast deterministic scan for obvious zero-day signatures."""
        for sig in self.basic_signatures:
            if re.search(sig, payload, re.IGNORECASE):
                return True
        return False

    async def headless_sandbox_check(self, payload):
        """
        DYNAMIC VERIFICATION: Injects payload into a headless browser.
        If it triggers a JavaScript execution, it's a confirmed attack.
        """
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Flag to check if JS executed (alerts, prompts, confirms)
                xss_triggered = {"status": False}
                page.on("dialog", lambda dialog: xss_triggered.update({"status": True}))
                
                # Inject payload into a blank Enterprise DOM
                html_content = f"<html><body>{payload}</body></html>"
                await page.set_content(html_content, timeout=3000)
                
                await browser.close()
                return xss_triggered["status"]
        except Exception as e:
            print(f"Sandbox Verification Error: {e}")
            return False