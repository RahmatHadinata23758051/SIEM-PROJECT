from __future__ import annotations

import argparse

from hybrid_siem.validation import load_feature_records_from_csv, validate_feature_records


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Hybrid SIEM feature dataset distributions.")
    parser.add_argument("--input", required=True, help="Path to feature CSV dataset.")
    parser.add_argument(
        "--histogram-bins",
        type=int,
        default=5,
        help="Number of histogram bins to use in the summary. Default: 5.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    records = load_feature_records_from_csv(args.input)
    report = validate_feature_records(records, histogram_bins=args.histogram_bins)
    print(report.render())


if __name__ == "__main__":
    main()
