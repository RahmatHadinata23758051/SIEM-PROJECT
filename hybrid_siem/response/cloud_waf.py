"""Cloud WAF Action Provider."""
from __future__ import annotations

import os

from hybrid_siem.response.base import ActionProvider, ActionRequest, ActionResult


class CloudflareWAFProvider(ActionProvider):
    """Executes blocks on Cloudflare WAF using their API."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
        self.zone_id = os.environ.get("CLOUDFLARE_ZONE_ID")
        self.account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID")

    async def execute(self, request: ActionRequest) -> ActionResult:
        if request.action_type not in ("block", "unblock"):
            return ActionResult(request.id, self.name, False, f"Unsupported action: {request.action_type}")

        if not self.api_token or not self.account_id:
            if self.dry_run:
                # If dry_run is true, we can mock success even without tokens
                print(f"[{self.name} DRY RUN] Would {request.action_type} IP {request.ip} on Cloudflare")
                return ActionResult(request.id, self.name, True, f"Dry run: {request.action_type} {request.ip}")
            return ActionResult(request.id, self.name, False, "Cloudflare credentials not configured")

        if self.dry_run:
            print(f"[{self.name} DRY RUN] API call ready: {request.action_type} {request.ip}")
            return ActionResult(request.id, self.name, True, f"Dry run API ready: {request.action_type}")

        import aiohttp
        
        # Cloudflare IP Access Rules API endpoint (Account level)
        url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/firewall/access_rules/rules"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        try:
            async with aiohttp.ClientSession() as session:
                if request.action_type == "block":
                    payload = {
                        "mode": "block",
                        "configuration": {
                            "target": "ip",
                            "value": request.ip
                        },
                        "notes": f"Blocked by Hybrid SIEM: {request.reason}"[:100]
                    }
                    async with session.post(url, headers=headers, json=payload, timeout=5.0) as response:
                        if response.status in (200, 201):
                            return ActionResult(request.id, self.name, True, "Cloudflare block rule created")
                        else:
                            err = await response.text()
                            return ActionResult(request.id, self.name, False, f"API Error ({response.status}): {err}")
                
                elif request.action_type == "unblock":
                    # Note: To unblock, you normally need the rule ID.
                    # A robust implementation would query the rule ID first, then delete it.
                    # For this implementation, we simulate the error if rule ID is unknown.
                    return ActionResult(request.id, self.name, False, "Unblock requires Rule ID lookup (Not Implemented)")
                    
        except Exception as e:
            return ActionResult(request.id, self.name, False, f"Network exception: {str(e)}")
        
        return ActionResult(request.id, self.name, False, "Unexpected execution path")
