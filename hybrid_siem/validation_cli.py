"""CLI for real log validation and failure analysis."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from hybrid_siem.anomaly import IsolationForestConfig, fit_isolation_forest
from hybrid_siem.calibration import select_likely_normal_records
from hybrid_siem.dataset import generate_feature_dataset
from hybrid_siem.features import build_feature_records
from hybrid_siem.parsers import parse_auth_log_file
from hybrid_siem.pipeline import process_feature_records
from hybrid_siem.risk import RiskWeights
from hybrid_siem.validation import load_feature_records_from_csv
from hybrid_siem.validation_analyzer import (
    analyze_decisions,
    generate_validation_summary,
    write_validation_traces,
)


def validate_real_logs(
    log_file: Path,
    output_dir: Path,
    baseline_csv: Path | None = None,
) -> None:
    """Run full validation pipeline on real logs.
    
    Args:
        log_file: Path to auth.log to validate
        output_dir: Output directory for results
        baseline_csv: Optional baseline CSV for comparison
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📖 Parsing log file: {log_file}")
    try:
        events = parse_auth_log_file(log_file)
        event_count = len(events)
        print(f"✓ Parsed {event_count} events")
    except Exception as e:
        print(f"❌ Failed to parse log: {e}")
        return
    
    print(f"🔍 Extracting features...")
    try:
        records = build_feature_records(events, window_seconds=60)
        record_count = len(records)
        unique_ips = len(set(r.ip for r in records))
        print(f"✓ Generated {record_count} feature records from {unique_ips} unique IPs")
    except Exception as e:
        print(f"❌ Failed to extract features: {e}")
        return
    
    # Train anomaly model on normal subset
    print(f"🤖 Training anomaly model...")
    try:
        normal_records = select_likely_normal_records(records)
        print(f"  Selected {len(normal_records)} normal records for training")
        
        config = IsolationForestConfig(
            feature_names=("failed_count", "username_variance", "inter_arrival_avg", "failed_ratio"),
            include_event_count=False,
        )
        model = fit_isolation_forest(normal_records, config=config)
        print(f"✓ Model trained successfully")
    except Exception as e:
        print(f"❌ Failed to train anomaly model: {e}")
        return
    
    # Run full pipeline
    print(f"📊 Processing through pipeline...")
    try:
        anomaly_scores = model.score_lookup(records)
        weights = RiskWeights(adaptive_boost=True)
        decisions = process_feature_records(
            records,
            weights=weights,
            anomaly_scores=anomaly_scores,
        )
        print(f"✓ Generated {len(decisions)} decisions")
    except Exception as e:
        print(f"❌ Failed to process pipeline: {e}")
        return
    
    # Analyze for failures
    print(f"⚠️  Analyzing for failure cases...")
    try:
        failure_cases, confidence_metrics = analyze_decisions(decisions)
        print(f"✓ Found {len(failure_cases)} potential failure cases")
    except Exception as e:
        print(f"❌ Failed to analyze failures: {e}")
        return
    
    # Generate summary
    print(f"📈 Generating summary...")
    summary = generate_validation_summary(decisions, failure_cases, confidence_metrics)
    
    # Write outputs
    print(f"💾 Writing results to {output_dir}...")
    
    # Trace CSV
    trace_path = output_dir / "validation_trace.csv"
    write_validation_traces(decisions, trace_path)
    print(f"  ✓ Trace: {trace_path}")
    
    # Failure cases
    failures_path = output_dir / "failure_cases.json"
    with failures_path.open("w") as f:
        json.dump(
            {
                "total": len(failure_cases),
                "by_type": {
                    "false_positive": sum(1 for fc in failure_cases if fc.case_type == "false_positive"),
                    "false_negative": sum(1 for fc in failure_cases if fc.case_type == "false_negative"),
                    "low_confidence": sum(1 for fc in failure_cases if fc.case_type == "low_confidence"),
                    "unusual_pattern": sum(1 for fc in failure_cases if fc.case_type == "unusual_pattern"),
                },
                "cases": [
                    {
                        "timestamp": fc.timestamp.isoformat(),
                        "ip": fc.ip,
                        "type": fc.case_type,
                        "risk_score": fc.risk_score,
                        "description": fc.description,
                        "evidence": fc.evidence,
                    }
                    for fc in failure_cases[:20]  # Top 20 for brevity
                ],
            },
            f,
            indent=2,
        )
    print(f"  ✓ Failures: {failures_path}")
    
    # Summary report
    summary_path = output_dir / "validation_summary.json"
    with summary_path.open("w") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_decisions": summary.total_decisions,
                    "mean_confidence": summary.mean_confidence,
                    "high_confidence_ratio": summary.high_confidence_ratio,
                    "unique_ips": len(set(d.feature_record.ip for d in decisions)),
                },
                "failures": {
                    "total": len(failure_cases),
                    "false_positive": sum(1 for fc in failure_cases if fc.case_type == "false_positive"),
                    "false_negative": sum(1 for fc in failure_cases if fc.case_type == "false_negative"),
                    "low_confidence": sum(1 for fc in failure_cases if fc.case_type == "low_confidence"),
                    "unusual_pattern": sum(1 for fc in failure_cases if fc.case_type == "unusual_pattern"),
                },
                "distribution_shift": summary.distribution_shift,
                "findings": summary.key_findings,
            },
            f,
            indent=2,
        )
    print(f"  ✓ Summary: {summary_path}")
    
    # Print findings
    print(f"\n📊 VALIDATION RESULTS")
    print(f"=" * 60)
    for finding in summary.key_findings:
        print(f"  {finding}")
    
    if failure_cases:
        print(f"\n⚠️  TOP FAILURE CASES")
        for i, fc in enumerate(failure_cases[:5], 1):
            print(f"  {i}. [{fc.case_type}] {fc.ip}: {fc.description}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m hybrid_siem.validation_cli <log_file> [output_dir]")
        sys.exit(1)
    
    log_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/generated/validation_results")
    
    if not log_path.exists():
        print(f"❌ Log file not found: {log_path}")
        sys.exit(1)
    
    validate_real_logs(log_path, output_path)
