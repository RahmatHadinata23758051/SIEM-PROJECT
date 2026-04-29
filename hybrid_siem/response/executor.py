"""Action Execution Queue for SOAR Responses."""
from __future__ import annotations

import asyncio
from datetime import datetime

from hybrid_siem.response.base import ActionProvider, ActionRequest, ActionResult


class ActionExecutionQueue:
    """Manages the execution of SOAR actions asynchronously.
    
    Provides a decoupled queue so that API event loops aren't blocked by slow
    OS commands or HTTP API calls.
    """

    def __init__(self, max_retries: int = 3):
        self.queue: asyncio.Queue[ActionRequest] = asyncio.Queue()
        self.providers: list[ActionProvider] = []
        self.max_retries = max_retries
        self.history: list[ActionResult] = []
        self._task: asyncio.Task | None = None

    def register_provider(self, provider: ActionProvider) -> None:
        """Register a mitigation provider (OS Firewall, WAF, etc.)."""
        self.providers.append(provider)

    def enqueue(self, request: ActionRequest) -> None:
        """Enqueue an action for execution."""
        try:
            self.queue.put_nowait(request)
        except asyncio.QueueFull:
            print("[ActionQueue] WARNING: Queue is full, dropping action request")

    async def _worker(self) -> None:
        """Background worker that consumes the action queue."""
        while True:
            try:
                request = await self.queue.get()
                await self._process_request(request)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[ActionQueue] Worker error: {e}")
                await asyncio.sleep(1)

    async def _process_request(self, request: ActionRequest) -> None:
        """Process a single action request across registered providers."""
        if not self.providers:
            print("[ActionQueue] WARNING: No providers registered, action ignored.")
            return

        for provider in self.providers:
            # Filter by provider type if specified
            if request.provider_type != "all":
                if request.provider_type == "os_firewall" and "OSFirewall" not in provider.name:
                    continue
                if request.provider_type == "cloud_waf" and "WAF" not in provider.name:
                    continue

            try:
                result = await provider.execute(request)
                self.history.append(result)
                
                if not result.success:
                    print(f"[ActionQueue] {provider.name} failed: {result.message}")
                    if request.retries < self.max_retries:
                        request.retries += 1
                        # Requeue with a small delay
                        asyncio.create_task(self._requeue_with_delay(request, delay=2.0))
                else:
                    print(f"[ActionQueue] {provider.name} SUCCESS: {result.message}")
                    
            except Exception as e:
                print(f"[ActionQueue] Exception in {provider.name}: {e}")
                
        # Maintain history size
        if len(self.history) > 100:
            self.history = self.history[-100:]

    async def _requeue_with_delay(self, request: ActionRequest, delay: float) -> None:
        await asyncio.sleep(delay)
        self.enqueue(request)

    def start(self) -> None:
        """Start the background worker."""
        if self._task is None:
            self._task = asyncio.create_task(self._worker())

    def stop(self) -> None:
        """Stop the background worker."""
        if self._task is not None:
            self._task.cancel()
            self._task = None

    def get_recent_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get the most recent execution results."""
        return [r.to_dict() for r in reversed(self.history[-limit:])]
