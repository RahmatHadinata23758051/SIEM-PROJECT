from __future__ import annotations

import argparse

from hybrid_siem.anomaly import IsolationForestConfig
from hybrid_siem.evaluation import generate_evaluation_bundle_from_csv
from hybrid_siem.risk import RiskWeights


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Hybrid SIEM calibration and evaluation on feature datasets.")
    parser.add_argument("--normal-dataset", required=True, help="Path to the normal-like feature CSV dataset.")
    parser.add_argument("--attack-dataset", help="Optional path to an attack-like feature CSV dataset.")
    parser.add_argument("--output-dir", required=True, help="Directory where reports, traces, and plots will be written.")
    parser.add_argument("--normal-label", default="normal_like", help="Display label for the normal dataset.")
    parser.add_argument("--attack-label", default="attack_like", help="Display label for the attack dataset.")
    parser.add_argument("--histogram-bins", type=int, default=10, help="Histogram bins for distribution plots. Default: 10.")
    parser.add_argument("--contamination", type=float, default=0.03, help="Isolation Forest contamination. Default: 0.03.")
    parser.add_argument("--n-estimators", type=int, default=200, help="Isolation Forest tree count. Default: 200.")
    parser.add_argument(
        "--scaler",
        choices=("standard", "minmax"),
        default="standard",
        help="Feature scaler for anomaly model. Default: standard.",
    )
    parser.add_argument(
        "--include-event-count",
        action="store_true",
        help="Include event_count in the anomaly model feature subset.",
    )
    parser.add_argument(
        "--smoothing-alpha",
        type=float,
        default=0.35,
        help="Per-IP exponential smoothing alpha for anomaly score. Default: 0.35.",
    )
    parser.add_argument("--rule-weight", type=float, default=1.00, help="Rule score weight in final risk. Default: 1.00.")
    parser.add_argument("--anomaly-weight", type=float, default=0.30, help="Anomaly score weight in final risk. Default: 0.30.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    anomaly_config = IsolationForestConfig(
        include_event_count=args.include_event_count,
        scaler=args.scaler,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        smoothing_alpha=args.smoothing_alpha,
    )
    risk_weights = RiskWeights(rule_weight=args.rule_weight, anomaly_weight=args.anomaly_weight)
    summary, artifacts = generate_evaluation_bundle_from_csv(
        normal_dataset_path=args.normal_dataset,
        attack_dataset_path=args.attack_dataset,
        output_dir=args.output_dir,
        normal_label=args.normal_label,
        attack_label=args.attack_label,
        histogram_bins=args.histogram_bins,
        anomaly_config=anomaly_config,
        risk_weights=risk_weights,
    )
    print(
        "Evaluation completed:",
        f"normal_rows={summary.normal_analysis.row_count}",
        f"attack_rows={summary.attack_analysis.row_count if summary.attack_analysis else 0}",
        f"report={artifacts.report_path}",
        f"thresholds={artifacts.thresholds_path}",
        f"model={artifacts.anomaly_model_path}",
        f"plots={len(artifacts.plot_paths)}",
    )


if __name__ == "__main__":
    main()
