from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from hybrid_siem.calibration import (
    CorrelationReport,
    DatasetFeatureAnalysis,
    ThresholdCalibrationReport,
    analyze_feature_distribution,
    calibrate_rule_thresholds_from_normal,
    compute_feature_correlations,
)
from hybrid_siem.models import FeatureRecord
from hybrid_siem.pipeline import PipelineDecision, process_feature_records
from hybrid_siem.scenarios import ScenarioDefinition, build_scenario_feature_sets
from hybrid_siem.validation import load_feature_records_from_csv


@dataclass(slots=True, frozen=True)
class ScenarioEvaluation:
    definition: ScenarioDefinition
    decisions: tuple[PipelineDecision, ...]


@dataclass(slots=True, frozen=True)
class EvaluationArtifacts:
    output_dir: Path
    report_path: Path
    thresholds_path: Path
    summary_path: Path
    trace_paths: tuple[Path, ...]
    plot_paths: tuple[Path, ...]


@dataclass(slots=True, frozen=True)
class EvaluationSummary:
    normal_analysis: DatasetFeatureAnalysis
    attack_analysis: DatasetFeatureAnalysis | None
    calibration: ThresholdCalibrationReport
    correlation: CorrelationReport
    scenarios: tuple[ScenarioEvaluation, ...]
    weaknesses: tuple[str, ...]

    def render_text(self) -> str:
        lines = [
            "Hybrid SIEM Evaluation Report",
            "",
            f"Normal dataset rows: {self.normal_analysis.row_count}",
            f"Attack dataset rows: {self.attack_analysis.row_count if self.attack_analysis else 0}",
            f"Calibration subset rows: {self.calibration.calibrated_row_count}/{self.calibration.baseline_row_count}",
            f"Calibration strategy: {self.calibration.selection_strategy}",
            "",
            "Calibrated Thresholds:",
        ]
        for key, value in asdict(self.calibration.thresholds).items():
            lines.append(f"- {key}: {value}")

        lines.append("")
        lines.append("Feature Distribution Summary:")
        for analysis in [self.normal_analysis, self.attack_analysis]:
            if analysis is None:
                continue
            lines.append(f"[{analysis.label}]")
            for feature_name, stats in analysis.feature_stats.items():
                lines.append(
                    f"- {feature_name}: mean={stats.mean:.4f} median={stats.median:.4f} std={stats.std:.4f} "
                    f"p50={stats.percentiles[50]:.4f} p75={stats.percentiles[75]:.4f} "
                    f"p90={stats.percentiles[90]:.4f} p95={stats.percentiles[95]:.4f} p99={stats.percentiles[99]:.4f}"
                )

        lines.append("")
        lines.append("Correlation With Risk Score:")
        for feature_name, correlation in self.correlation.feature_to_risk.items():
            lines.append(f"- {feature_name}: {correlation:.4f}")

        lines.append("")
        lines.append("Scenario Decision Traces:")
        for scenario in self.scenarios:
            metrics = _scenario_metrics(scenario)
            lines.append(
                f"[{scenario.definition.name}] {scenario.definition.description} "
                f"peak_risk={metrics['peak_risk']:.2f} final_risk={metrics['final_risk']:.2f} "
                f"peak_action={metrics['peak_action']} final_action={metrics['final_action']}"
            )
            for decision in scenario.decisions:
                lines.append(
                    f"- {decision.feature_record.timestamp.isoformat(sep=' ')} "
                    f"ip={decision.feature_record.ip} event_count={decision.feature_record.event_count} "
                    f"rule={decision.rule_score} risk={decision.risk_score:.2f} action={decision.action}"
                )

        lines.append("")
        lines.append("Identified Weaknesses:")
        if self.weaknesses:
            lines.extend(f"- {weakness}" for weakness in self.weaknesses)
        else:
            lines.append("- No immediate critical weakness detected in current synthetic evaluation.")
        return "\n".join(lines)


def _load_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError:
        return None


def _plot_feature_histograms(
    normal_analysis: DatasetFeatureAnalysis,
    attack_analysis: DatasetFeatureAnalysis | None,
    output_dir: Path,
) -> list[Path]:
    plt = _load_matplotlib()
    if plt is None:
        return []

    plot_paths: list[Path] = []
    for feature_name, normal_stats in normal_analysis.feature_stats.items():
        figure, axis = plt.subplots(figsize=(8, 4))
        normal_positions = range(len(normal_stats.histogram_counts))
        axis.bar(normal_positions, normal_stats.histogram_counts, alpha=0.6, label=normal_analysis.label)

        if attack_analysis is not None:
            attack_stats = attack_analysis.feature_stats[feature_name]
            axis.plot(
                list(normal_positions),
                list(attack_stats.histogram_counts),
                color="crimson",
                marker="o",
                label=attack_analysis.label,
            )

        axis.set_title(f"{feature_name} distribution")
        axis.set_xlabel("histogram bin")
        axis.set_ylabel("count")
        axis.legend()
        figure.tight_layout()
        path = output_dir / f"{feature_name}_distribution.png"
        figure.savefig(path)
        plt.close(figure)
        plot_paths.append(path)

    return plot_paths


def _plot_scenario_traces(
    scenarios: tuple[ScenarioEvaluation, ...],
    output_dir: Path,
) -> list[Path]:
    plt = _load_matplotlib()
    if plt is None:
        return []

    plot_paths: list[Path] = []
    for scenario in scenarios:
        timestamps = [decision.feature_record.timestamp for decision in scenario.decisions]
        risk_scores = [decision.risk_score for decision in scenario.decisions]
        event_counts = [decision.feature_record.event_count for decision in scenario.decisions]

        figure, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
        axes[0].plot(timestamps, risk_scores, marker="o", color="darkred")
        axes[0].set_ylabel("risk_score")
        axes[0].set_title(f"{scenario.definition.name} risk over time")
        axes[0].grid(True, alpha=0.25)

        axes[1].plot(timestamps, event_counts, marker="s", color="steelblue")
        axes[1].set_ylabel("event_count")
        axes[1].set_xlabel("timestamp")
        axes[1].grid(True, alpha=0.25)
        figure.tight_layout()

        path = output_dir / f"{scenario.definition.name}_trace.png"
        figure.savefig(path)
        plt.close(figure)
        plot_paths.append(path)

    return plot_paths


def _plot_correlation_heatmap(correlation: CorrelationReport, output_dir: Path) -> Path | None:
    plt = _load_matplotlib()
    if plt is None:
        return None

    import numpy as np

    features = list(correlation.feature_to_feature.keys())
    matrix = np.array([[correlation.feature_to_feature[left][right] for right in features] for left in features], dtype=float)
    figure, axis = plt.subplots(figsize=(7, 6))
    heatmap = axis.imshow(matrix, cmap="coolwarm", vmin=-1, vmax=1)
    axis.set_xticks(range(len(features)))
    axis.set_xticklabels(features, rotation=45, ha="right")
    axis.set_yticks(range(len(features)))
    axis.set_yticklabels(features)
    axis.set_title("feature correlation heatmap")
    figure.colorbar(heatmap, ax=axis)
    figure.tight_layout()
    path = output_dir / "feature_correlation_heatmap.png"
    figure.savefig(path)
    plt.close(figure)
    return path


def _write_trace_csv(scenario: ScenarioEvaluation, output_dir: Path) -> Path:
    path = output_dir / f"{scenario.definition.name}_trace.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "ip", "failed_count", "request_rate", "username_variance", "failed_ratio", "event_count", "rule_score", "risk_score", "action"])
        for decision in scenario.decisions:
            record = decision.feature_record
            writer.writerow(
                [
                    record.timestamp.isoformat(sep=" "),
                    record.ip,
                    record.failed_count,
                    record.request_rate,
                    record.username_variance,
                    record.failed_ratio,
                    record.event_count,
                    decision.rule_score,
                    decision.risk_score,
                    decision.action,
                ]
            )
    return path


def _action_rank(action: str) -> int:
    mapping = {
        "normal": 0,
        "monitor": 1,
        "rate_limit": 2,
        "block": 3,
    }
    return mapping.get(action, -1)


def _group_decisions_by_ip(decisions: tuple[PipelineDecision, ...]) -> dict[str, list[PipelineDecision]]:
    grouped: dict[str, list[PipelineDecision]] = {}
    for decision in decisions:
        grouped.setdefault(decision.feature_record.ip, []).append(decision)
    return grouped


def _is_non_decreasing(values: list[float], tolerance: float = 1.0) -> bool:
    return all(values[index + 1] + tolerance >= values[index] for index in range(len(values) - 1))


def _scenario_metrics(scenario: ScenarioEvaluation) -> dict[str, object]:
    if not scenario.decisions:
        return {
            "name": scenario.definition.name,
            "peak_risk": 0.0,
            "final_risk": 0.0,
            "peak_action": "normal",
            "final_action": "normal",
            "ip_count": 0,
            "per_ip_final_risk": {},
        }

    grouped = _group_decisions_by_ip(scenario.decisions)
    peak_risk = max(decision.risk_score for decision in scenario.decisions)
    peak_action = max((decision.action for decision in scenario.decisions), key=_action_rank)
    final_action = scenario.decisions[-1].action
    return {
        "name": scenario.definition.name,
        "peak_risk": peak_risk,
        "final_risk": scenario.decisions[-1].risk_score,
        "peak_action": peak_action,
        "final_action": final_action,
        "ip_count": len(grouped),
        "per_ip_final_risk": {
            ip: decisions[-1].risk_score
            for ip, decisions in grouped.items()
        },
    }


def _identify_weaknesses(summary: EvaluationSummary) -> tuple[str, ...]:
    weaknesses: list[str] = []

    correlation_pairs = summary.correlation.feature_to_feature
    for left_name, mapping in correlation_pairs.items():
        for right_name, value in mapping.items():
            if left_name >= right_name:
                continue
            if abs(value) >= 0.92:
                weaknesses.append(f"Potential feature redundancy: {left_name} vs {right_name} correlation {value:.2f}")

    for scenario in summary.scenarios:
        if not scenario.decisions:
            weaknesses.append(f"Scenario {scenario.definition.name} produced no decisions.")
            continue

        if scenario.definition.expected_action_ceiling is not None:
            allowed_rank = _action_rank(scenario.definition.expected_action_ceiling)
            observed_peak_rank = max(_action_rank(decision.action) for decision in scenario.decisions)
            if observed_peak_rank > allowed_rank:
                weaknesses.append(
                    f"Scenario {scenario.definition.name} exceeded action ceiling {scenario.definition.expected_action_ceiling}."
                )

        if scenario.definition.expected_peak_action is not None:
            observed_peak_action = max((decision.action for decision in scenario.decisions), key=_action_rank)
            if _action_rank(observed_peak_action) < _action_rank(scenario.definition.expected_peak_action):
                weaknesses.append(
                    f"Scenario {scenario.definition.name} never reached expected peak action {scenario.definition.expected_peak_action}."
                )

        if scenario.definition.expected_final_action is not None:
            observed_final_action = scenario.decisions[-1].action
            if observed_final_action != scenario.definition.expected_final_action:
                weaknesses.append(
                    f"Scenario {scenario.definition.name} ended with {observed_final_action}, expected {scenario.definition.expected_final_action}."
                )

    normal_typo = next((scenario for scenario in summary.scenarios if scenario.definition.name == "normal_typo"), None)
    if normal_typo:
        peak_risk = max(decision.risk_score for decision in normal_typo.decisions)
        if peak_risk >= 60:
            weaknesses.append("Normal typo scenario escalated into medium-or-higher risk.")

    slow_attack = next((scenario for scenario in summary.scenarios if scenario.definition.name == "slow_bruteforce"), None)
    if slow_attack:
        grouped = _group_decisions_by_ip(slow_attack.decisions)
        primary_track = max(grouped.values(), key=len)
        risk_series = [decision.risk_score for decision in primary_track]
        peak_risk = max(risk_series)
        peak_index = risk_series.index(peak_risk)
        ramp = risk_series[: peak_index + 1]

        if peak_risk < 60:
            weaknesses.append("Slow brute force never reached medium risk.")
        if len(ramp) >= 2 and not _is_non_decreasing(ramp):
            weaknesses.append("Slow brute force risk did not climb gradually before the peak.")
        if peak_index < len(risk_series) - 1 and risk_series[-1] >= peak_risk:
            weaknesses.append("Slow brute force did not decay after the quiet period.")

    aggressive = next((scenario for scenario in summary.scenarios if scenario.definition.name == "aggressive_bruteforce"), None)
    if aggressive:
        grouped = _group_decisions_by_ip(aggressive.decisions)
        primary_track = max(grouped.values(), key=len)
        risk_series = [decision.risk_score for decision in primary_track]
        peak_risk = max(risk_series)
        peak_index = risk_series.index(peak_risk)
        if peak_risk < 80:
            weaknesses.append("Aggressive brute force did not spike into high risk.")
        if peak_index == len(risk_series) - 1 or risk_series[-1] >= peak_risk:
            weaknesses.append("Aggressive brute force did not show decay after quiet period.")

    distributed = next((scenario for scenario in summary.scenarios if scenario.definition.name == "distributed_attack"), None)
    if distributed:
        grouped = _group_decisions_by_ip(distributed.decisions)
        if not any(
            len(track) >= 2 and track[-1].risk_score > track[0].risk_score
            for track in grouped.values()
        ):
            weaknesses.append("Distributed attack did not accumulate risk over time.")
        if not all(
            len(track) >= 2 and _is_non_decreasing([decision.risk_score for decision in track])
            for track in grouped.values()
        ):
            weaknesses.append("Distributed attack risk was not gradually increasing per IP.")

    return tuple(dict.fromkeys(weaknesses))


def evaluate_scenarios(
    thresholds_report: ThresholdCalibrationReport,
) -> tuple[ScenarioEvaluation, ...]:
    scenario_evaluations: list[ScenarioEvaluation] = []
    for definition, records in build_scenario_feature_sets():
        decisions = process_feature_records(records, thresholds=thresholds_report.thresholds)
        scenario_evaluations.append(ScenarioEvaluation(definition=definition, decisions=tuple(decisions)))
    return tuple(scenario_evaluations)


def generate_evaluation_bundle(
    normal_records: list[FeatureRecord],
    attack_records: list[FeatureRecord] | None,
    output_dir: str | Path,
    normal_label: str = "normal_like",
    attack_label: str = "attack_like",
    histogram_bins: int = 10,
) -> tuple[EvaluationSummary, EvaluationArtifacts]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    normal_analysis = analyze_feature_distribution(normal_records, label=normal_label, histogram_bins=histogram_bins)
    attack_analysis = (
        analyze_feature_distribution(attack_records, label=attack_label, histogram_bins=histogram_bins)
        if attack_records is not None
        else None
    )
    calibration = calibrate_rule_thresholds_from_normal(normal_records, source_label=normal_label)

    combined_records = list(normal_records) + list(attack_records or [])
    combined_decisions = process_feature_records(combined_records, thresholds=calibration.thresholds)
    correlation = compute_feature_correlations(
        combined_records,
        risk_scores=[decision.risk_score for decision in combined_decisions],
    )
    scenarios = evaluate_scenarios(calibration)

    summary = EvaluationSummary(
        normal_analysis=normal_analysis,
        attack_analysis=attack_analysis,
        calibration=calibration,
        correlation=correlation,
        scenarios=scenarios,
        weaknesses=tuple(),
    )
    summary = EvaluationSummary(
        normal_analysis=summary.normal_analysis,
        attack_analysis=summary.attack_analysis,
        calibration=summary.calibration,
        correlation=summary.correlation,
        scenarios=summary.scenarios,
        weaknesses=_identify_weaknesses(summary),
    )

    report_path = out_dir / "evaluation_report.txt"
    report_path.write_text(summary.render_text(), encoding="utf-8")

    thresholds_path = out_dir / "calibrated_thresholds.json"
    thresholds_path.write_text(json.dumps(calibration.as_dict(), indent=2), encoding="utf-8")

    summary_path = out_dir / "evaluation_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "normal_analysis": asdict(normal_analysis),
                "attack_analysis": asdict(attack_analysis) if attack_analysis else None,
                "calibration": calibration.as_dict(),
                "correlation": asdict(correlation),
                "scenarios": [_scenario_metrics(scenario) for scenario in scenarios],
                "weaknesses": list(summary.weaknesses),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    trace_paths = tuple(_write_trace_csv(scenario, out_dir) for scenario in scenarios)
    plot_paths_list = _plot_feature_histograms(normal_analysis, attack_analysis, out_dir) + _plot_scenario_traces(
        scenarios, out_dir
    )
    correlation_plot = _plot_correlation_heatmap(correlation, out_dir)
    if correlation_plot is not None:
        plot_paths_list.append(correlation_plot)
    plot_paths = tuple(plot_paths_list)

    artifacts = EvaluationArtifacts(
        output_dir=out_dir,
        report_path=report_path,
        thresholds_path=thresholds_path,
        summary_path=summary_path,
        trace_paths=trace_paths,
        plot_paths=plot_paths,
    )
    return summary, artifacts


def generate_evaluation_bundle_from_csv(
    normal_dataset_path: str | Path,
    attack_dataset_path: str | Path | None,
    output_dir: str | Path,
    normal_label: str = "normal_like",
    attack_label: str = "attack_like",
    histogram_bins: int = 10,
) -> tuple[EvaluationSummary, EvaluationArtifacts]:
    normal_records = load_feature_records_from_csv(normal_dataset_path)
    attack_records = load_feature_records_from_csv(attack_dataset_path) if attack_dataset_path else None
    return generate_evaluation_bundle(
        normal_records=normal_records,
        attack_records=attack_records,
        output_dir=output_dir,
        normal_label=normal_label,
        attack_label=attack_label,
        histogram_bins=histogram_bins,
    )
