from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from hybrid_siem.models import FeatureRecord

class CorrelationEngine:
    def __init__(self, window_size_seconds: int = 120):
        self.window = window_size_seconds
        self.ip_history: Dict[str, List[FeatureRecord]] = defaultdict(list)
        
    def _cleanup_old_records(self, current_time: datetime, ip: str) -> None:
        cutoff_time = current_time - timedelta(seconds=self.window)
        self.ip_history[ip] = [
            record for record in self.ip_history[ip] 
            if record.timestamp > cutoff_time
        ]

    def evaluate(self, current_record: FeatureRecord) -> Tuple[float, List[str]]:
        ip = current_record.ip
        self.ip_history[ip].append(current_record)
        self._cleanup_old_records(current_record.timestamp, ip)
        
        correlation_penalty = 0.0
        reasons = []
        
        # Aggregate history over the window
        total_ssh_fails = sum(r.ssh_failed_count for r in self.ip_history[ip])
        total_http_404s = sum(r.http_404_count for r in self.ip_history[ip])
        total_events = sum(r.event_count for r in self.ip_history[ip])
        
        # Rule 1: SSH Brute Force + HTTP Vulnerability Scanning
        if total_ssh_fails > 3 and total_http_404s > 10:
            correlation_penalty += 30.0
            reasons.append("Cross-source: SSH brute force combined with HTTP scanning")
            
        # Rule 2: Multi-vector high activity
        unique_source_types = set()
        for r in self.ip_history[ip]:
            if r.ssh_total_attempts > 0 or r.failed_count > 0: unique_source_types.add("ssh")
            if r.http_total_requests > 0: unique_source_types.add("http")
            
        if len(unique_source_types) > 1 and total_events > 20:
            correlation_penalty += 20.0
            reasons.append(f"Multi-vector attack: High activity across {len(unique_source_types)} services")

        # Rule 3: Low-intensity persistence (Slow attack)
        if len(self.ip_history[ip]) > 5 and total_events < 15:
            # Consistent but low volume
            correlation_penalty += 10.0
            reasons.append("Persistent low-intensity probing detected")
                
        return correlation_penalty, reasons
