from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from hybrid_siem.models import SshAuthAttempt, SshAuthEvent

PRIMARY_ATTEMPT_EVENT_TYPES = {"failed_password", "accepted_auth"}
SECONDARY_ATTEMPT_EVENT_TYPES = {"invalid_user", "pam_auth_failure"}


@dataclass(slots=True)
class _AttemptAccumulator:
    ip: str
    port: int | None
    session_id: str | None
    first_timestamp: datetime
    last_timestamp: datetime
    canonical_timestamp: datetime
    outcome: str
    primary_username: str | None
    usernames: list[str] = field(default_factory=list)
    source_event_types: list[str] = field(default_factory=list)
    event_count: int = 0
    anchored_by_primary: bool = False


def _same_identity(event: SshAuthEvent, attempt: _AttemptAccumulator) -> bool:
    if not event.ip or event.ip != attempt.ip:
        return False

    same_session = bool(event.session_id and attempt.session_id and event.session_id == attempt.session_id)
    same_port = bool(event.port is not None and attempt.port is not None and event.port == attempt.port)
    return same_session or same_port


def _within_window(event: SshAuthEvent, attempt: _AttemptAccumulator, dedup_window_seconds: int) -> bool:
    return (event.timestamp - attempt.last_timestamp).total_seconds() <= dedup_window_seconds


def _can_merge_secondary(event: SshAuthEvent, attempt: _AttemptAccumulator) -> bool:
    if event.outcome == "failure" and attempt.outcome == "success":
        return False
    return True


def _merge_event(event: SshAuthEvent, attempt: _AttemptAccumulator, anchored_by_primary: bool) -> None:
    attempt.last_timestamp = event.timestamp
    attempt.event_count += 1
    attempt.source_event_types.append(event.event_type)

    if event.username and event.username not in attempt.usernames:
        attempt.usernames.append(event.username)
        attempt.primary_username = event.username

    if anchored_by_primary:
        attempt.anchored_by_primary = True
        attempt.canonical_timestamp = event.timestamp
        attempt.outcome = event.outcome
        if event.port is not None:
            attempt.port = event.port
        if event.session_id:
            attempt.session_id = event.session_id
    elif event.port is not None and attempt.port is None:
        attempt.port = event.port


def _new_attempt(event: SshAuthEvent, anchored_by_primary: bool) -> _AttemptAccumulator:
    return _AttemptAccumulator(
        ip=event.ip or "",
        port=event.port,
        session_id=event.session_id,
        first_timestamp=event.timestamp,
        last_timestamp=event.timestamp,
        canonical_timestamp=event.timestamp,
        outcome=event.outcome,
        primary_username=event.username,
        usernames=[event.username] if event.username else [],
        source_event_types=[event.event_type],
        event_count=1,
        anchored_by_primary=anchored_by_primary,
    )


def _find_primary_merge_target(
    event: SshAuthEvent,
    attempts: list[_AttemptAccumulator],
    dedup_window_seconds: int,
) -> _AttemptAccumulator | None:
    for attempt in reversed(attempts):
        if attempt.anchored_by_primary:
            continue
        if not _same_identity(event, attempt):
            continue
        if not _within_window(event, attempt, dedup_window_seconds):
            continue
        return attempt
    return None


def _find_secondary_merge_target(
    event: SshAuthEvent,
    attempts: list[_AttemptAccumulator],
    dedup_window_seconds: int,
) -> _AttemptAccumulator | None:
    for attempt in reversed(attempts):
        if not _same_identity(event, attempt):
            continue
        if not _within_window(event, attempt, dedup_window_seconds):
            continue
        if not _can_merge_secondary(event, attempt):
            continue
        return attempt
    return None


def build_canonical_attempts(
    events: Iterable[SshAuthEvent],
    dedup_window_seconds: int = 3,
) -> list[SshAuthAttempt]:
    if dedup_window_seconds <= 0:
        raise ValueError("dedup_window_seconds must be greater than zero")

    signal_events = [
        event
        for event in sorted(events, key=lambda item: (item.timestamp, item.line_number))
        if event.is_attempt and event.ip
    ]

    attempts: list[_AttemptAccumulator] = []
    for event in signal_events:
        if event.event_type in PRIMARY_ATTEMPT_EVENT_TYPES:
            merge_target = _find_primary_merge_target(event, attempts, dedup_window_seconds)
            if merge_target:
                _merge_event(event, merge_target, anchored_by_primary=True)
            else:
                attempts.append(_new_attempt(event, anchored_by_primary=True))
            continue

        merge_target = _find_secondary_merge_target(event, attempts, dedup_window_seconds)
        if merge_target:
            _merge_event(event, merge_target, anchored_by_primary=False)
        else:
            attempts.append(_new_attempt(event, anchored_by_primary=False))

    canonical_attempts: list[SshAuthAttempt] = []
    for index, attempt in enumerate(attempts, start=1):
        canonical_attempts.append(
            SshAuthAttempt(
                attempt_id=f"{attempt.ip}:{attempt.session_id or 'no-session'}:{index}",
                timestamp=attempt.canonical_timestamp,
                ip=attempt.ip,
                port=attempt.port,
                session_id=attempt.session_id,
                outcome=attempt.outcome,
                primary_username=attempt.primary_username,
                usernames=tuple(attempt.usernames),
                source_event_types=tuple(attempt.source_event_types),
                event_count=attempt.event_count,
            )
        )

    return canonical_attempts
