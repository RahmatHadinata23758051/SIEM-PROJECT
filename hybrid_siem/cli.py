from __future__ import annotations

import argparse
from datetime import datetime

from hybrid_siem.dataset import generate_feature_dataset


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SSH auth feature dataset for Hybrid SIEM Phase 1.")
    parser.add_argument("--input", required=True, help="Path to auth.log input file.")
    parser.add_argument("--output", required=True, help="Path to generated CSV output.")
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=60,
        help="Aggregation window in seconds. Default: 60.",
    )
    parser.add_argument(
        "--reference-time",
        help="Optional ISO timestamp used to infer the log year, example: 2026-04-28T10:30:00",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    reference_time = datetime.fromisoformat(args.reference_time) if args.reference_time else None
    result = generate_feature_dataset(
        input_path=args.input,
        output_path=args.output,
        window_seconds=args.window_seconds,
        reference_time=reference_time,
    )
    print(
        "Generated dataset:",
        f"parsed_events={result.parsed_events}",
        f"counted_attempts={result.counted_attempts}",
        f"feature_rows={result.feature_rows}",
        f"output={result.output_path}",
    )


if __name__ == "__main__":
    main()
