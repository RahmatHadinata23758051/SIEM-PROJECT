from __future__ import annotations

import argparse

from hybrid_siem.evaluation import generate_evaluation_bundle_from_csv


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Hybrid SIEM calibration and evaluation on feature datasets.")
    parser.add_argument("--normal-dataset", required=True, help="Path to the normal-like feature CSV dataset.")
    parser.add_argument("--attack-dataset", help="Optional path to an attack-like feature CSV dataset.")
    parser.add_argument("--output-dir", required=True, help="Directory where reports, traces, and plots will be written.")
    parser.add_argument("--normal-label", default="normal_like", help="Display label for the normal dataset.")
    parser.add_argument("--attack-label", default="attack_like", help="Display label for the attack dataset.")
    parser.add_argument("--histogram-bins", type=int, default=10, help="Histogram bins for distribution plots. Default: 10.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    summary, artifacts = generate_evaluation_bundle_from_csv(
        normal_dataset_path=args.normal_dataset,
        attack_dataset_path=args.attack_dataset,
        output_dir=args.output_dir,
        normal_label=args.normal_label,
        attack_label=args.attack_label,
        histogram_bins=args.histogram_bins,
    )
    print(
        "Evaluation completed:",
        f"normal_rows={summary.normal_analysis.row_count}",
        f"attack_rows={summary.attack_analysis.row_count if summary.attack_analysis else 0}",
        f"report={artifacts.report_path}",
        f"thresholds={artifacts.thresholds_path}",
        f"plots={len(artifacts.plot_paths)}",
    )


if __name__ == "__main__":
    main()
