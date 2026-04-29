"""Base interfaces for Active Threat Response (SOAR)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


@dataclass
class ActionRequest:
    """Represents a request to execute a mitigation action."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip: str = ""
    action_type: Literal["block", "unblock", "rate_limit"] = "block"
    provider_type: Literal["os_firewall", "cloud_waf", "all"] = "all"
    reason: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    retries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ip": self.ip,
            "action_type": self.action_type,
            "provider_type": self.provider_type,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() + "Z",
            "retries": self.retries,
        }


@dataclass
class ActionResult:
    """Represents the outcome of a mitigation action."""
    request_id: str
    provider_name: str
    success: bool
    message: str
    executed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "provider_name": self.provider_name,
            "success": self.success,
            "message": self.message,
            "executed_at": self.executed_at.isoformat() + "Z",
        }


class ActionProvider:
    """Base interface for all response providers."""
    
    @property
    def name(self) -> str:
        return self.__class__.__name__

    async def execute(self, request: ActionRequest) -> ActionResult:
        """Execute the action. Must be implemented by subclasses."""
        raise NotImplementedError
