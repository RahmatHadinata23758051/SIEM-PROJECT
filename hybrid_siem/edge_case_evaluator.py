"""Edge case evaluation and analysis."""

from __future__ import annotations

import json
from pathlib import Path

from hybrid_siem.anomaly import IsolationForestConfig, fit_isolation_forest
from hybrid_siem.calibration import select_likely_normal_records
from hybrid_siem.perturbation_analyzer import PerturbationAnalyzer
from hybrid_siem.pipeline import process_feature_records
from hybrid_siem.risk import RiskWeights
from hybrid_siem.scenarios import build_scenario_feature_sets
from hybrid_siem.validation_analyzer import (
    analyze_decisions,
    generate_validation_summary,
    write_validation_traces,
)


def evaluate_edge_cases(output_dir: Path) -> None:
    """Evaluate all edge case scenarios.
    
    Args:
        output_dir: Directory to write results
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("🔍 Building scenario feature sets...")
    feature_sets = build_scenario_feature_sets()
    
    # Filter for edge case scenarios
    edge_cases = [
        (defn, records) for defn, records in feature_sets
        if any(x in defn.name for x in ["burst", "successful", "rotating", "noise"])
    ]
    
    print(f"✓ Found {len(edge_cases)} edge case scenarios")
    
    # Aggregate all records for training
    all_records = []
    for _, records in edge_cases:
        all_records.extend(records)
    
    # Train anomaly model
    print("🤖 Training anomaly model on edge case data...")
    normal_records = select_likely_normal_records(all_records)
    print(f"  Selected {len(normal_records)} normal records for training")
    
    config = IsolationForestConfig()
    model = fit_isolation_forest(normal_records, config=config)
    
    # Evaluate each edge case
    results = {}
    
    for scenario_def, records in edge_cases:
        print(f"\n📊 Evaluating: {scenario_def.name}")
        print(f"   {scenario_def.description}")
        
        # Run pipeline
        anomaly_scores = model.score_lookup(records)
        weights = RiskWeights(adaptive_boost=True)
        decisions = process_feature_records(
            records,
            weights=weights,
            anomaly_scores=anomaly_scores,
        )
        
        # Analyze
        failure_cases, confidence_metrics = analyze_decisions(decisions)
        summary = generate_validation_summary(decisions, failure_cases, confidence_metrics)
        
        # Write traces
        trace_file = output_dir / f"{scenario_def.name}_trace.csv"
        write_validation_traces(decisions, trace_file)
        
        # Perturbation analysis on interesting record (highest risk)
        if decisions:
            interesting_decision = max(decisions, key=lambda d: d.risk_score)
            record = interesting_decision.feature_record
            
            analyzer = PerturbationAnalyzer()
            perturbation_results = analyzer.analyze_feature_sensitivity(record, model)
            
            sensitivity_summary = {
                "record_ip": record.ip,
                "record_timestamp": record.timestamp.isoformat(),
                "baseline_score": interesting_decision.risk_score,
                "features": [
                    {
                        "name": r.feature_name,
                        "baseline": r.baseline_score,
                        "sensitivity": r.sensitivity,
                        "max_change": r.max_change,
                        "significance": r.significance,
                    }
                    for r in perturbation_results
                ],
            }
        else:
            sensitivity_summary = {"error": "No decisions"}
        
        # Store results
        results[scenario_def.name] = {
            "description": scenario_def.description,
            "expected_final_action": scenario_def.expected_final_action,
            "statistics": {
                "total_windows": summary.total_decisions,
                "unique_ips": len(set(d.feature_record.ip for d in decisions)),
                "mean_confidence": summary.mean_confidence,
                "high_confidence_ratio": summary.high_confidence_ratio,
            },
            "failures": {
                "total": len(failure_cases),
                "false_positive": sum(1 for f in failure_cases if f.case_type == "false_positive"),
                "false_negative": sum(1 for f in failure_cases if f.case_type == "false_negative"),
                "low_confidence": sum(1 for f in failure_cases if f.case_type == "low_confidence"),
                "unusual_pattern": sum(1 for f in failure_cases if f.case_type == "unusual_pattern"),
            },
            "sensitivity_analysis": sensitivity_summary,
            "findings": summary.key_findings,
            "trace_file": str(trace_file),
        }
        
        # Print summary
        print(f"   ✓ Windows: {summary.total_decisions}, Mean confidence: {summary.mean_confidence}")
        if failure_cases:
            print(f"   ⚠️  Failures: {len(failure_cases)}")
    
    # Write comprehensive report
    report_file = output_dir / "edge_case_analysis.json"
    with report_file.open("w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results written to {report_file}")
    
    # Print summary
    print("\n📈 EDGE CASE ANALYSIS SUMMARY")
    print("=" * 70)
    for scenario_name, result in results.items():
        failures = result["failures"]["total"]
        confidence = result["statistics"]["mean_confidence"]
        status = "⚠️ " if failures > 0 or confidence < 0.7 else "✅"
        print(f"{status} {scenario_name:30s} Conf: {confidence:.2f}  Failures: {failures}")


if __name__ == "__main__":
    output_path = Path("data/generated/edge_case_results")
    evaluate_edge_cases(output_path)
