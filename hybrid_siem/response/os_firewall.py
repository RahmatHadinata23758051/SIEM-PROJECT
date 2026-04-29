"""OS Firewall Action Provider."""
from __future__ import annotations

import asyncio
import ipaddress
import platform
import subprocess

from hybrid_siem.response.base import ActionProvider, ActionRequest, ActionResult


class OSFirewallProvider(ActionProvider):
    """Executes OS-level firewall commands to block IPs.
    
    Supports Linux (iptables, ufw) and Windows (netsh).
    Includes strict IP validation to prevent command injection.
    """

    def __init__(self, engine: str = "auto", dry_run: bool = True):
        """
        Args:
            engine: 'iptables', 'ufw', 'netsh', or 'auto'
            dry_run: If True, logs the command instead of executing it.
        """
        self.dry_run = dry_run
        self.engine = engine
        if self.engine == "auto":
            self_os = platform.system().lower()
            self.engine = "netsh" if self_os == "windows" else "iptables"

    def _is_valid_ip(self, ip: str) -> bool:
        """Strict IP validation to prevent command injection."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _build_command(self, action: str, ip: str) -> list[str]:
        if self.engine == "iptables":
            if action == "block":
                return ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            elif action == "unblock":
                return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        
        elif self.engine == "ufw":
            if action == "block":
                return ["ufw", "insert", "1", "deny", "from", ip]
            elif action == "unblock":
                return ["ufw", "delete", "deny", "from", ip]
                
        elif self.engine == "netsh":
            rule_name = f"SIEM_BLOCK_{ip}"
            if action == "block":
                return [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
                ]
            elif action == "unblock":
                return [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
        
        raise ValueError(f"Unsupported engine/action: {self.engine}/{action}")

    async def execute(self, request: ActionRequest) -> ActionResult:
        if request.action_type not in ("block", "unblock"):
            return ActionResult(request.id, self.name, False, f"Unsupported action: {request.action_type}")
            
        if not self._is_valid_ip(request.ip):
            return ActionResult(request.id, self.name, False, f"Invalid IP address: {request.ip}")

        try:
            cmd = self._build_command(request.action_type, request.ip)
        except Exception as e:
            return ActionResult(request.id, self.name, False, str(e))

        cmd_str = " ".join(cmd)
        
        if self.dry_run:
            print(f"[{self.name} DRY RUN] Would execute: {cmd_str}")
            return ActionResult(request.id, self.name, True, f"Dry run: {cmd_str}")

        try:
            # Run blocking subprocess in a thread pool
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return ActionResult(request.id, self.name, True, f"Executed: {cmd_str}")
            else:
                err_msg = stderr.decode().strip() or stdout.decode().strip()
                return ActionResult(request.id, self.name, False, f"Failed ({process.returncode}): {err_msg}")
                
        except Exception as e:
            return ActionResult(request.id, self.name, False, f"Exception: {str(e)}")
