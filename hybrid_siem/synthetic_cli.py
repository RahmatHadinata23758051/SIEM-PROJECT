from __future__ import annotations

import argparse
from datetime import datetime

from hybrid_siem.synthetic import build_synthetic_training_corpus


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a large synthetic SSH log corpus and feature dataset.")
    parser.add_argument("--auth-log", required=True, help="Path to generated synthetic auth.log file.")
    parser.add_argument("--dataset", required=True, help="Path to generated feature CSV file.")
    parser.add_argument(
        "--target-csv-mb",
        type=float,
        default=5.0,
        help="Minimum target size for the generated CSV in MB. Default: 5.0.",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic generation.")
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=60,
        help="Aggregation window in seconds for feature extraction. Default: 60.",
    )
    parser.add_argument(
        "--start-time",
        default="2026-01-01T00:00:00",
        help="ISO timestamp for the first synthetic log minute. Default: 2026-01-01T00:00:00.",
    )
    parser.add_argument(
        "--behavior-profile",
        choices=["mixed", "honeypot"],
        default="mixed",
        help="Traffic profile to generate. Use 'honeypot' for illegal-login-heavy SSH traffic.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = build_synthetic_training_corpus(
        auth_log_path=args.auth_log,
        dataset_path=args.dataset,
        target_csv_size_mb=args.target_csv_mb,
        seed=args.seed,
        window_seconds=args.window_seconds,
        start_time=datetime.fromisoformat(args.start_time),
        behavior_profile=args.behavior_profile,
    )
    print(
        "Generated synthetic corpus:",
        f"profile={result.behavior_profile}",
        f"feature_rows={result.dataset_result.feature_rows}",
        f"parsed_events={result.dataset_result.parsed_events}",
        f"counted_attempts={result.dataset_result.counted_attempts}",
        f"csv_mb={result.dataset_size_bytes / (1024 * 1024):.2f}",
        f"auth_log_mb={result.auth_log_size_bytes / (1024 * 1024):.2f}",
        f"minutes={result.minutes_covered}",
        f"auth_log={result.auth_log_path}",
        f"dataset={result.dataset_path}",
    )


if __name__ == "__main__":
    main()
