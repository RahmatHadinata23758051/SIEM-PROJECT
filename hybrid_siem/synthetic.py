from __future__ import annotations

import ipaddress
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from hybrid_siem.dataset import DatasetBuildResult, generate_feature_dataset

MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

FIRST_NAMES = [
    "adi",
    "agus",
    "akbar",
    "aldi",
    "amelia",
    "anisa",
    "ardi",
    "arya",
    "ayu",
    "bagas",
    "bella",
    "bima",
    "cahya",
    "citra",
    "dewi",
    "dian",
    "eka",
    "fikri",
    "galih",
    "gina",
    "hani",
    "ibnu",
    "indah",
    "intan",
    "joko",
    "laila",
    "mira",
    "nabila",
    "nurul",
    "putri",
    "rahmat",
    "ratna",
    "reza",
    "riko",
    "rina",
    "sari",
    "sinta",
    "tiara",
    "wulan",
    "yogi",
]

LAST_NAMES = [
    "anwar",
    "aryanto",
    "firdaus",
    "gunawan",
    "hakim",
    "haryanto",
    "hermawan",
    "istiqomah",
    "kurniawan",
    "maulana",
    "mulyadi",
    "nurhadi",
    "permata",
    "prabowo",
    "prasetyo",
    "putra",
    "rahardjo",
    "ramadhan",
    "saputra",
    "setiawan",
    "subekti",
    "sulistyo",
    "surya",
    "syahputra",
    "utama",
    "wahyudi",
    "widodo",
    "wijaya",
]

ATTACK_USERNAMES = [
    "admin",
    "administrator",
    "adm",
    "ansible",
    "backup",
    "centos",
    "cisco",
    "deployer",
    "deploy",
    "devops",
    "ec2-user",
    "git",
    "guest",
    "jenkins",
    "mysql",
    "nagios",
    "nobody",
    "operator",
    "oracle",
    "postgres",
    "root",
    "support",
    "sysadmin",
    "test",
    "tomcat",
    "ubuntu",
    "user",
    "vagrant",
    "www-data",
]

SERVICE_USERS = [
    "backup_sync",
    "deploy_bot",
    "metrics_agent",
    "ansible_runner",
    "log_shipper",
    "db_mirror",
    "cache_warmer",
    "scheduler",
    "replication",
    "vault_agent",
    "monitoring",
    "artifact_pull",
]


@dataclass(slots=True, frozen=True)
class SyntheticIdentity:
    username: str
    role: str
    auth_method: str
    schedule: str
    primary_ip: str
    secondary_ip: str | None
    uses_shared_vpn: bool


@dataclass(slots=True, frozen=True)
class ThreatCampaign:
    kind: str
    source_ips: tuple[str, ...]
    usernames: tuple[str, ...]
    known_targets: tuple[str, ...]
    end_time: datetime


@dataclass(slots=True, frozen=True)
class SyntheticAuthLogBuildResult:
    output_path: Path
    feature_rows_targeted: int
    feature_rows_emitted: int
    parsed_line_count: int
    minutes_covered: int
    start_time: datetime
    end_time: datetime


@dataclass(slots=True, frozen=True)
class SyntheticCorpusBuildResult:
    auth_log_path: Path
    dataset_path: Path
    dataset_result: DatasetBuildResult
    auth_log_size_bytes: int
    dataset_size_bytes: int
    minutes_covered: int
    feature_rows_targeted: int
    feature_rows_emitted: int
    start_time: datetime
    end_time: datetime
    behavior_profile: str


class SyntheticSshLogGenerator:
    def __init__(self, seed: int = 42, host: str = "ubuntu", behavior_profile: str = "mixed") -> None:
        if behavior_profile not in {"mixed", "honeypot"}:
            raise ValueError("behavior_profile must be either 'mixed' or 'honeypot'")

        self.rng = random.Random(seed)
        self.host = host
        self.behavior_profile = behavior_profile
        self.pid_counter = 2000
        self.office_private_pool = self._build_private_pool("10.24", 240)
        self.branch_private_pool = self._build_private_pool("192.168", 180, third_octet_range=range(40, 90))
        self.remote_public_pool = self._build_public_pool(260)
        self.shared_vpn_pool = self._build_public_pool(40)
        self.attack_ip_pool = self._build_public_pool(900)
        self.known_users = self._build_known_users()
        self.identities = self._build_identities()
        self.identity_index = {identity.username: identity for identity in self.identities}
        self.attackable_users = [identity.username for identity in self.identities if identity.role != "service"]
        self.identity_by_schedule: dict[str, list[SyntheticIdentity]] = {}
        for identity in self.identities:
            self.identity_by_schedule.setdefault(identity.schedule, []).append(identity)

        attack_variants = {f"{username}{suffix}" for username in ATTACK_USERNAMES for suffix in ("", "1", "01", "123")}
        legal_variants = {
            f"{username.split('.')[0]}{suffix}" for username in self.attackable_users[:120] for suffix in ("", "01", "2024")
        }
        self.attack_username_pool = sorted(
            set(ATTACK_USERNAMES) | attack_variants | legal_variants | set(self.attackable_users)
        )

    def build_auth_log(
        self,
        output_path: str | Path,
        target_feature_rows: int,
        start_time: datetime,
    ) -> SyntheticAuthLogBuildResult:
        if target_feature_rows <= 0:
            raise ValueError("target_feature_rows must be greater than zero")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        feature_rows_emitted = 0
        parsed_line_count = 0
        minute_cursor = start_time
        active_campaigns: list[ThreatCampaign] = []
        minutes_covered = 0

        with path.open("w", encoding="utf-8") as handle:
            while feature_rows_emitted < target_feature_rows:
                active_campaigns = [campaign for campaign in active_campaigns if campaign.end_time >= minute_cursor]
                active_campaigns.extend(self._maybe_start_campaigns(minute_cursor))
                rows_emitted, lines_written = self._write_minute(handle, minute_cursor, active_campaigns)
                feature_rows_emitted += rows_emitted
                parsed_line_count += lines_written
                minute_cursor += timedelta(minutes=1)
                minutes_covered += 1

        return SyntheticAuthLogBuildResult(
            output_path=path,
            feature_rows_targeted=target_feature_rows,
            feature_rows_emitted=feature_rows_emitted,
            parsed_line_count=parsed_line_count,
            minutes_covered=minutes_covered,
            start_time=start_time,
            end_time=minute_cursor,
        )

    def _build_known_users(self) -> list[str]:
        usernames: list[str] = []
        for first_name in FIRST_NAMES:
            for last_name in LAST_NAMES:
                usernames.append(f"{first_name}.{last_name}")
                if len(usernames) >= 180:
                    return usernames
        return usernames

    def _build_identities(self) -> list[SyntheticIdentity]:
        identities: list[SyntheticIdentity] = []
        office_users = self.known_users[:110]
        flex_users = self.known_users[110:150]
        night_users = self.known_users[150:180]
        admin_users = [f"ops-{index:02d}" for index in range(1, 13)]

        for username in office_users:
            primary_ip = self.rng.choice(self.office_private_pool)
            secondary_ip = self.rng.choice(self.shared_vpn_pool) if self.rng.random() < 0.45 else None
            auth_method = self.rng.choices(["password", "publickey"], weights=[0.65, 0.35], k=1)[0]
            identities.append(
                SyntheticIdentity(
                    username=username,
                    role="employee",
                    auth_method=auth_method,
                    schedule="office",
                    primary_ip=primary_ip,
                    secondary_ip=secondary_ip,
                    uses_shared_vpn=secondary_ip is not None,
                )
            )

        for username in flex_users:
            primary_ip = self.rng.choice(self.remote_public_pool)
            secondary_ip = self.rng.choice(self.shared_vpn_pool) if self.rng.random() < 0.5 else None
            auth_method = self.rng.choices(["password", "publickey"], weights=[0.55, 0.45], k=1)[0]
            identities.append(
                SyntheticIdentity(
                    username=username,
                    role="contractor",
                    auth_method=auth_method,
                    schedule="flex",
                    primary_ip=primary_ip,
                    secondary_ip=secondary_ip,
                    uses_shared_vpn=secondary_ip is not None,
                )
            )

        for username in night_users:
            primary_ip = self.rng.choice(self.branch_private_pool)
            secondary_ip = self.rng.choice(self.shared_vpn_pool) if self.rng.random() < 0.35 else None
            identities.append(
                SyntheticIdentity(
                    username=username,
                    role="night_ops",
                    auth_method="publickey",
                    schedule="night",
                    primary_ip=primary_ip,
                    secondary_ip=secondary_ip,
                    uses_shared_vpn=secondary_ip is not None,
                )
            )

        for username in admin_users:
            primary_ip = self.rng.choice(self.shared_vpn_pool)
            secondary_ip = self.rng.choice(self.remote_public_pool)
            identities.append(
                SyntheticIdentity(
                    username=username,
                    role="admin",
                    auth_method=self.rng.choices(["publickey", "password"], weights=[0.75, 0.25], k=1)[0],
                    schedule="flex",
                    primary_ip=primary_ip,
                    secondary_ip=secondary_ip,
                    uses_shared_vpn=True,
                )
            )

        for index, username in enumerate(SERVICE_USERS):
            primary_ip = self.office_private_pool[index % len(self.office_private_pool)]
            identities.append(
                SyntheticIdentity(
                    username=username,
                    role="service",
                    auth_method="publickey",
                    schedule="automation",
                    primary_ip=primary_ip,
                    secondary_ip=None,
                    uses_shared_vpn=False,
                )
            )

        return identities

    def _build_private_pool(
        self,
        prefix: str,
        count: int,
        third_octet_range: range = range(10, 60),
    ) -> list[str]:
        pool: set[str] = set()
        first, second = prefix.split(".")
        while len(pool) < count:
            third = self.rng.choice(tuple(third_octet_range))
            fourth = self.rng.randint(10, 240)
            pool.add(f"{first}.{second}.{third}.{fourth}")
        return sorted(pool)

    def _build_public_pool(self, count: int) -> list[str]:
        pool: set[str] = set()
        while len(pool) < count:
            candidate = ipaddress.ip_address(self.rng.getrandbits(32))
            if any(
                (
                    candidate.is_private,
                    candidate.is_loopback,
                    candidate.is_link_local,
                    candidate.is_multicast,
                    candidate.is_reserved,
                    candidate.is_unspecified,
                )
            ):
                continue
            pool.add(str(candidate))
        return sorted(pool)

    def _maybe_start_campaigns(self, minute: datetime) -> list[ThreatCampaign]:
        campaigns: list[ThreatCampaign] = []
        bruteforce_prob = 0.004 if self.behavior_profile == "mixed" else 0.045
        spray_prob = 0.0018 if self.behavior_profile == "mixed" else 0.022
        scanner_prob = 0.0035 if self.behavior_profile == "mixed" else 0.038
        stuffing_prob = 0.0013 if self.behavior_profile == "mixed" else 0.016

        if self.rng.random() < bruteforce_prob:
            campaigns.append(
                ThreatCampaign(
                    kind="bruteforce",
                    source_ips=(self.rng.choice(self.attack_ip_pool),),
                    usernames=tuple(
                        self.rng.sample(
                            self.attack_username_pool,
                            k=self.rng.randint(18, 45) if self.behavior_profile == "mixed" else self.rng.randint(28, 60),
                        )
                    ),
                    known_targets=tuple(self.rng.sample(self.attackable_users, k=3)),
                    end_time=minute
                    + timedelta(minutes=self.rng.randint(8, 28) if self.behavior_profile == "mixed" else self.rng.randint(18, 48)),
                )
            )
        if self.rng.random() < spray_prob:
            campaigns.append(
                ThreatCampaign(
                    kind="password_spray",
                    source_ips=tuple(
                        self.rng.sample(
                            self.attack_ip_pool,
                            k=self.rng.randint(12, 30) if self.behavior_profile == "mixed" else self.rng.randint(20, 45),
                        )
                    ),
                    usernames=tuple(
                        self.rng.sample(
                            self.attackable_users,
                            k=self.rng.randint(8, 18) if self.behavior_profile == "mixed" else self.rng.randint(12, 24),
                        )
                    ),
                    known_targets=tuple(self.rng.sample(self.attackable_users, k=6)),
                    end_time=minute
                    + timedelta(minutes=self.rng.randint(25, 120) if self.behavior_profile == "mixed" else self.rng.randint(40, 180)),
                )
            )
        if self.rng.random() < scanner_prob:
            campaigns.append(
                ThreatCampaign(
                    kind="scanner",
                    source_ips=(self.rng.choice(self.attack_ip_pool),),
                    usernames=tuple(
                        self.rng.sample(
                            self.attack_username_pool,
                            k=self.rng.randint(12, 24) if self.behavior_profile == "mixed" else self.rng.randint(18, 36),
                        )
                    ),
                    known_targets=tuple(),
                    end_time=minute
                    + timedelta(minutes=self.rng.randint(20, 90) if self.behavior_profile == "mixed" else self.rng.randint(30, 120)),
                )
            )
        if self.rng.random() < stuffing_prob:
            campaigns.append(
                ThreatCampaign(
                    kind="credential_stuffing",
                    source_ips=(self.rng.choice(self.attack_ip_pool),),
                    usernames=tuple(
                        self.rng.sample(
                            self.attackable_users,
                            k=self.rng.randint(5, 10) if self.behavior_profile == "mixed" else self.rng.randint(8, 16),
                        )
                    ),
                    known_targets=tuple(self.rng.sample(self.attackable_users, k=2)),
                    end_time=minute
                    + timedelta(minutes=self.rng.randint(12, 48) if self.behavior_profile == "mixed" else self.rng.randint(20, 72)),
                )
            )
        return campaigns

    def _write_minute(
        self,
        handle,
        minute: datetime,
        active_campaigns: list[ThreatCampaign],
    ) -> tuple[int, int]:
        activities: list[tuple[str, list[tuple[int, str]]]] = []
        used_ips: set[str] = set()

        for campaign in active_campaigns:
            for ip, sequence in self._build_campaign_activities(campaign, minute):
                if ip in used_ips or not sequence:
                    continue
                used_ips.add(ip)
                activities.append((ip, sequence))

        benign_window_count = self._choose_benign_window_count(minute)
        for _ in range(benign_window_count):
            if self.rng.random() < 0.12:
                ip, sequence = self._build_shared_vpn_activity(minute)
            elif self.rng.random() < 0.08:
                ip, sequence = self._build_noisy_automation_activity(minute)
            else:
                identity = self._select_identity_for_minute(minute)
                ip, sequence = self._build_identity_activity(identity, minute)

            if ip in used_ips or not sequence:
                continue
            used_ips.add(ip)
            activities.append((ip, sequence))

        lines_written = 0
        for ip, sequence in activities:
            del ip
            for line in self._materialize_lines(minute, sequence):
                handle.write(line)
                lines_written += 1

        return len(activities), lines_written

    def _choose_benign_window_count(self, minute: datetime) -> int:
        if self.behavior_profile == "honeypot":
            return self.rng.choices([0, 1, 2], weights=[0.72, 0.24, 0.04], k=1)[0]

        weekday = minute.weekday()
        hour = minute.hour
        if weekday < 5 and 8 <= hour < 18:
            return self.rng.choices([1, 2, 3, 4, 5], weights=[0.06, 0.24, 0.31, 0.26, 0.13], k=1)[0]
        if weekday < 5 and 18 <= hour < 23:
            return self.rng.choices([0, 1, 2, 3], weights=[0.18, 0.36, 0.31, 0.15], k=1)[0]
        if weekday >= 5 and 9 <= hour < 20:
            return self.rng.choices([0, 1, 2, 3], weights=[0.22, 0.38, 0.28, 0.12], k=1)[0]
        if 0 <= hour < 6:
            return self.rng.choices([0, 1, 2], weights=[0.56, 0.34, 0.1], k=1)[0]
        return self.rng.choices([0, 1, 2, 3], weights=[0.34, 0.36, 0.2, 0.1], k=1)[0]

    def _select_identity_for_minute(self, minute: datetime) -> SyntheticIdentity:
        if self.behavior_profile == "honeypot":
            schedule = self.rng.choices(
                ["automation", "flex", "admin", "office"],
                weights=[0.55, 0.17, 0.18, 0.10],
                k=1,
            )[0]
            if schedule == "admin":
                return self.rng.choice([identity for identity in self.identities if identity.role == "admin"])
            return self.rng.choice(self.identity_by_schedule[schedule])

        weekday = minute.weekday()
        hour = minute.hour
        if weekday < 5 and 8 <= hour < 18:
            schedule = self.rng.choices(
                ["office", "flex", "automation", "night"],
                weights=[0.62, 0.17, 0.16, 0.05],
                k=1,
            )[0]
        elif 18 <= hour < 23:
            schedule = self.rng.choices(
                ["flex", "office", "automation", "night"],
                weights=[0.35, 0.18, 0.24, 0.23],
                k=1,
            )[0]
        elif 0 <= hour < 6:
            schedule = self.rng.choices(
                ["night", "automation", "flex"],
                weights=[0.4, 0.46, 0.14],
                k=1,
            )[0]
        else:
            schedule = self.rng.choices(
                ["office", "flex", "automation", "night"],
                weights=[0.24, 0.28, 0.28, 0.2],
                k=1,
            )[0]

        return self.rng.choice(self.identity_by_schedule[schedule])

    def _pick_identity_ip(self, identity: SyntheticIdentity) -> str:
        if self.behavior_profile == "honeypot" and identity.role != "service":
            return self.rng.choice(self.remote_public_pool if self.rng.random() < 0.75 else self.shared_vpn_pool)
        if identity.secondary_ip and self.rng.random() < 0.22:
            return identity.secondary_ip
        return identity.primary_ip

    def _build_identity_activity(
        self,
        identity: SyntheticIdentity,
        minute: datetime,
    ) -> tuple[str, list[tuple[int, str]]]:
        ip = self._pick_identity_ip(identity)
        if identity.role == "service":
            return ip, self._generate_service_sequence(identity, ip)
        if identity.role in {"admin", "night_ops"}:
            return ip, self._generate_privileged_sequence(identity, ip)
        return ip, self._generate_human_sequence(identity, ip, minute)

    def _build_shared_vpn_activity(self, minute: datetime) -> tuple[str, list[tuple[int, str]]]:
        candidates = [identity for identity in self.identities if identity.uses_shared_vpn and identity.role != "service"]
        selected = self.rng.sample(candidates, k=self.rng.randint(2, 4))
        ip = self.rng.choice(self.shared_vpn_pool)
        sequence: list[tuple[int, str]] = []
        for index, identity in enumerate(selected):
            base_offset = min(55, index * self.rng.randint(8, 16))
            sequence.extend(self._generate_human_sequence(identity, ip, minute, forced_offset=base_offset))
        return ip, sequence

    def _build_noisy_automation_activity(self, minute: datetime) -> tuple[str, list[tuple[int, str]]]:
        identity = self.rng.choice(self.identity_by_schedule["automation"])
        ip = identity.primary_ip if self.behavior_profile == "mixed" else self.rng.choice(self.remote_public_pool)
        sequence: list[tuple[int, str]] = []
        failure_count = self.rng.randint(3, 8) if self.behavior_profile == "mixed" else self.rng.randint(5, 12)
        offsets = self._spread_offsets(failure_count + 1, 0, 58)
        for offset in offsets[:failure_count]:
            port = self._next_port()
            sequence.append((offset, self._pam_failure_message(identity.username, ip)))
            sequence.append((min(59, offset + 1), self._failed_password_message(identity.username, ip, port)))
        success_probability = 0.55 if self.behavior_profile == "mixed" else 0.12
        if self.rng.random() < success_probability:
            sequence.append((min(59, offsets[-1] + 1), self._accepted_message(identity, ip, self._next_port())))
        else:
            sequence.append(
                (59, self._disconnect_message("authenticating", identity.username, ip, self._next_port()))
            )
        return ip, sequence

    def _generate_human_sequence(
        self,
        identity: SyntheticIdentity,
        ip: str,
        minute: datetime,
        forced_offset: int | None = None,
    ) -> list[tuple[int, str]]:
        del minute
        sequence: list[tuple[int, str]] = []
        failure_count = 0
        base_failure_probability = 0.14 if self.behavior_profile == "mixed" else 0.45
        multi_failure_probability = 0.035 if self.behavior_profile == "mixed" else 0.16

        if self.rng.random() < base_failure_probability:
            failure_count = 1
        if self.rng.random() < multi_failure_probability:
            failure_count = self.rng.randint(2, 4) if self.behavior_profile == "mixed" else self.rng.randint(3, 7)

        if self.behavior_profile == "honeypot":
            success_count = 1 if self.rng.random() < 0.18 else 0
        else:
            success_count = 1 if self.rng.random() < 0.88 else 2
        total_markers = max(1, failure_count + success_count)
        offsets = self._spread_offsets(total_markers, forced_offset, 58)

        offset_index = 0
        for _ in range(failure_count):
            port = self._next_port()
            if self.rng.random() < 0.2:
                sequence.append((offsets[offset_index], self._pam_failure_message(identity.username, ip)))
                sequence.append((min(59, offsets[offset_index] + 1), self._failed_password_message(identity.username, ip, port)))
            else:
                sequence.append((offsets[offset_index], self._failed_password_message(identity.username, ip, port)))
            offset_index += 1

        for _ in range(success_count):
            sequence.append((offsets[offset_index], self._accepted_message(identity, ip, self._next_port())))
            offset_index += 1

        if self.behavior_profile == "honeypot" and success_count == 0:
            sequence.append((59, self._disconnect_message("authenticating", identity.username, ip, self._next_port())))

        return sequence

    def _generate_privileged_sequence(self, identity: SyntheticIdentity, ip: str) -> list[tuple[int, str]]:
        sequence: list[tuple[int, str]] = []
        if self.behavior_profile == "honeypot":
            failure_count = self.rng.randint(1, 4)
            success_count = 1 if self.rng.random() < 0.08 else 0
        else:
            failure_count = 0 if self.rng.random() < 0.8 else self.rng.randint(1, 2)
            success_count = self.rng.randint(1, 2)
        offsets = self._spread_offsets(failure_count + success_count, 0, 56)

        offset_index = 0
        for _ in range(failure_count):
            sequence.append((offsets[offset_index], self._failed_password_message(identity.username, ip, self._next_port())))
            offset_index += 1

        for _ in range(success_count):
            sequence.append((offsets[offset_index], self._accepted_message(identity, ip, self._next_port())))
            offset_index += 1

        if self.behavior_profile == "honeypot" and success_count == 0:
            sequence.append((59, self._disconnect_message("authenticating", identity.username, ip, self._next_port())))

        return sequence

    def _generate_service_sequence(self, identity: SyntheticIdentity, ip: str) -> list[tuple[int, str]]:
        if self.behavior_profile == "honeypot":
            if self.rng.random() < 0.72:
                failure_count = self.rng.randint(2, 6)
                offsets = self._spread_offsets(failure_count, 0, 56)
                sequence = [
                    (offset, self._failed_password_message(identity.username, ip, self._next_port()))
                    for offset in offsets
                ]
                sequence.append((59, self._disconnect_message("authenticating", identity.username, ip, self._next_port())))
                return sequence

        success_count = self.rng.choices([1, 2, 3], weights=[0.6, 0.3, 0.1], k=1)[0]
        offsets = self._spread_offsets(success_count, 0, 55)
        return [(offset, self._accepted_message(identity, ip, self._next_port())) for offset in offsets]

    def _build_campaign_activities(
        self,
        campaign: ThreatCampaign,
        minute: datetime,
    ) -> list[tuple[str, list[tuple[int, str]]]]:
        if campaign.kind == "bruteforce":
            ip = campaign.source_ips[0]
            return [(ip, self._generate_bruteforce_sequence(ip, campaign))]
        if campaign.kind == "password_spray":
            active_ip_count = min(len(campaign.source_ips), self.rng.randint(2, 6))
            selected_ips = self.rng.sample(list(campaign.source_ips), k=active_ip_count)
            return [(ip, self._generate_password_spray_sequence(ip, campaign)) for ip in selected_ips]
        if campaign.kind == "scanner":
            ip = campaign.source_ips[0]
            if minute.minute % self.rng.randint(2, 5) != 0:
                return []
            return [(ip, self._generate_scanner_sequence(ip, campaign))]
        if campaign.kind == "credential_stuffing":
            ip = campaign.source_ips[0]
            return [(ip, self._generate_credential_stuffing_sequence(ip, campaign))]
        return []

    def _generate_bruteforce_sequence(
        self,
        ip: str,
        campaign: ThreatCampaign,
    ) -> list[tuple[int, str]]:
        attempt_count = self.rng.randint(16, 44) if self.behavior_profile == "mixed" else self.rng.randint(26, 70)
        offsets = self._spread_offsets(attempt_count, 0, 58)
        sequence: list[tuple[int, str]] = []
        usernames = [self.rng.choice(campaign.usernames) for _ in range(attempt_count)]
        for offset, username in zip(offsets, usernames):
            port = self._next_port()
            invalid_probability = 0.72 if self.behavior_profile == "mixed" else 0.88
            invalid_user_log_probability = 0.65 if self.behavior_profile == "mixed" else 0.82
            pam_probability = 0.28 if self.behavior_profile == "mixed" else 0.4

            is_invalid = username not in self.identity_index and self.rng.random() < invalid_probability
            if is_invalid and self.rng.random() < invalid_user_log_probability:
                sequence.append((offset, self._invalid_user_message(username, ip, port)))
                offset = min(59, offset + 1)
            sequence.append((offset, self._failed_password_message(username, ip, port, invalid_user=is_invalid)))
            if self.rng.random() < pam_probability:
                sequence.append((min(59, offset + 1), self._pam_failure_message(username, ip)))

        success_probability = 0.04 if self.behavior_profile == "mixed" else 0.003
        if self.rng.random() < success_probability:
            target = self.rng.choice(campaign.known_targets)
            identity = self.identity_index[target]
            sequence.append((59, self._accepted_message(identity, ip, self._next_port())))
        elif self.rng.random() < 0.72:
            closing_user = self.rng.choice(usernames)
            sequence.append((59, self._disconnect_message("authenticating", closing_user, ip, self._next_port())))

        return sequence

    def _generate_password_spray_sequence(
        self,
        ip: str,
        campaign: ThreatCampaign,
    ) -> list[tuple[int, str]]:
        attempt_count = self.rng.randint(3, 8) if self.behavior_profile == "mixed" else self.rng.randint(5, 12)
        offsets = self._spread_offsets(attempt_count, 0, 57)
        sequence: list[tuple[int, str]] = []
        usernames = self.rng.sample(list(campaign.usernames), k=min(attempt_count, len(campaign.usernames)))
        while len(usernames) < attempt_count:
            usernames.append(self.rng.choice(campaign.usernames))

        for offset, username in zip(offsets, usernames):
            port = self._next_port()
            sequence.append((offset, self._failed_password_message(username, ip, port)))
            if self.rng.random() < (0.14 if self.behavior_profile == "mixed" else 0.25):
                sequence.append((min(59, offset + 1), self._pam_failure_message(username, ip)))

        if self.rng.random() < (0.01 if self.behavior_profile == "mixed" else 0.002):
            target = self.rng.choice(campaign.known_targets)
            identity = self.identity_index[target]
            sequence.append((59, self._accepted_message(identity, ip, self._next_port())))

        return sequence

    def _generate_scanner_sequence(
        self,
        ip: str,
        campaign: ThreatCampaign,
    ) -> list[tuple[int, str]]:
        attempt_count = self.rng.randint(1, 4) if self.behavior_profile == "mixed" else self.rng.randint(3, 8)
        offsets = self._spread_offsets(attempt_count, 0, 55)
        sequence: list[tuple[int, str]] = []
        usernames = self.rng.sample(list(campaign.usernames), k=attempt_count)

        for offset, username in zip(offsets, usernames):
            port = self._next_port()
            if self.rng.random() < (0.8 if self.behavior_profile == "mixed" else 0.93):
                sequence.append((offset, self._invalid_user_message(username, ip, port)))
                offset = min(59, offset + 1)
            sequence.append((offset, self._failed_password_message(username, ip, port, invalid_user=True)))

        if self.rng.random() < 0.7:
            sequence.append((59, self._disconnect_message("invalid", self.rng.choice(usernames), ip, self._next_port())))
        return sequence

    def _generate_credential_stuffing_sequence(
        self,
        ip: str,
        campaign: ThreatCampaign,
    ) -> list[tuple[int, str]]:
        attempt_count = self.rng.randint(8, 16) if self.behavior_profile == "mixed" else self.rng.randint(12, 22)
        offsets = self._spread_offsets(attempt_count, 0, 58)
        sequence: list[tuple[int, str]] = []
        usernames = [self.rng.choice(campaign.usernames) for _ in range(attempt_count)]
        for offset, username in zip(offsets, usernames):
            port = self._next_port()
            sequence.append((offset, self._failed_password_message(username, ip, port)))
            if self.rng.random() < (0.18 if self.behavior_profile == "mixed" else 0.28):
                sequence.append((min(59, offset + 1), self._pam_failure_message(username, ip)))

        if self.rng.random() < (0.12 if self.behavior_profile == "mixed" else 0.01):
            target = self.rng.choice(campaign.known_targets)
            identity = self.identity_index[target]
            sequence.append((59, self._accepted_message(identity, ip, self._next_port())))

        return sequence

    def _spread_offsets(
        self,
        count: int,
        forced_start: int | None,
        max_second: int,
    ) -> list[int]:
        if count <= 0:
            return []

        start = forced_start if forced_start is not None else self.rng.randint(0, max(0, max_second // 4))
        if count == 1:
            return [min(max_second, start)]

        span = max(1, max_second - start)
        step = max(1, span // max(1, count - 1))
        offsets: list[int] = []
        for index in range(count):
            jitter = self.rng.randint(0, min(3, step))
            offsets.append(min(max_second, start + (index * step) + jitter))
        offsets.sort()
        return offsets

    def _materialize_lines(self, minute: datetime, sequence: list[tuple[int, str]]) -> list[str]:
        lines: list[str] = []
        for offset, message in sorted(sequence, key=lambda item: item[0]):
            timestamp = minute + timedelta(seconds=max(0, min(59, offset)))
            lines.append(self._format_syslog_line(timestamp, message))
        return lines

    def _format_syslog_line(self, timestamp: datetime, message: str) -> str:
        month_name = MONTH_NAMES[timestamp.month - 1]
        clock = timestamp.strftime("%H:%M:%S")
        pid = self._next_pid()
        return f"{month_name} {timestamp.day:>2} {clock} {self.host} sshd[{pid}]: {message}\n"

    def _accepted_message(self, identity: SyntheticIdentity, ip: str, port: int) -> str:
        return f"Accepted {identity.auth_method} for {identity.username} from {ip} port {port} ssh2"

    def _failed_password_message(self, username: str, ip: str, port: int, invalid_user: bool = False) -> str:
        if invalid_user:
            return f"Failed password for invalid user {username} from {ip} port {port} ssh2"
        return f"Failed password for {username} from {ip} port {port} ssh2"

    def _invalid_user_message(self, username: str, ip: str, port: int) -> str:
        return f"Invalid user {username} from {ip} port {port}"

    def _pam_failure_message(self, username: str, ip: str) -> str:
        return (
            "pam_unix(sshd:auth): authentication failure; "
            f"logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={username}"
        )

    def _disconnect_message(self, qualifier: str, username: str, ip: str, port: int) -> str:
        if qualifier == "invalid":
            return f"Disconnected from invalid user {username} {ip} port {port} [preauth]"
        return f"Connection closed by authenticating user {username} {ip} port {port} [preauth]"

    def _next_pid(self) -> int:
        self.pid_counter += 1
        return self.pid_counter

    def _next_port(self) -> int:
        return self.rng.randint(32768, 60999)


def build_synthetic_training_corpus(
    auth_log_path: str | Path,
    dataset_path: str | Path,
    target_csv_size_mb: float = 5.0,
    seed: int = 42,
    window_seconds: int = 60,
    start_time: datetime | None = None,
    behavior_profile: str = "mixed",
) -> SyntheticCorpusBuildResult:
    if target_csv_size_mb <= 0:
        raise ValueError("target_csv_size_mb must be greater than zero")

    target_bytes = int(target_csv_size_mb * 1024 * 1024)
    feature_row_target = max(500, int(math.ceil(target_csv_size_mb * 20_000)))
    base_start_time = start_time or datetime(2026, 1, 1, 0, 0, 0)

    while True:
        generator = SyntheticSshLogGenerator(seed=seed, behavior_profile=behavior_profile)
        auth_result = generator.build_auth_log(
            output_path=auth_log_path,
            target_feature_rows=feature_row_target,
            start_time=base_start_time,
        )
        reference_time = auth_result.end_time + timedelta(hours=1)
        dataset_result = generate_feature_dataset(
            input_path=auth_log_path,
            output_path=dataset_path,
            window_seconds=window_seconds,
            reference_time=reference_time,
        )
        dataset_size_bytes = Path(dataset_path).stat().st_size
        if dataset_size_bytes >= target_bytes:
            auth_log_size_bytes = Path(auth_log_path).stat().st_size
            return SyntheticCorpusBuildResult(
                auth_log_path=Path(auth_log_path),
                dataset_path=Path(dataset_path),
                dataset_result=dataset_result,
                auth_log_size_bytes=auth_log_size_bytes,
                dataset_size_bytes=dataset_size_bytes,
                minutes_covered=auth_result.minutes_covered,
                feature_rows_targeted=feature_row_target,
                feature_rows_emitted=auth_result.feature_rows_emitted,
                start_time=auth_result.start_time,
                end_time=auth_result.end_time,
                behavior_profile=behavior_profile,
            )

        bytes_per_row = dataset_size_bytes / max(1, dataset_result.feature_rows)
        feature_row_target = int(math.ceil((target_bytes / max(1.0, bytes_per_row)) * 1.08))
