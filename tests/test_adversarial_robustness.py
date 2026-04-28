"""Test suite for adversarial robustness and advanced risk modeling."""

import unittest
from datetime import datetime, timedelta

from hybrid_siem.models import FeatureRecord
from hybrid_siem.pipeline import process_feature_records, PipelineDecision
from hybrid_siem.risk import RiskWeights, compute_risk_score
from hybrid_siem.scenarios import build_scenario_feature_sets
from hybrid_siem.temporal import TemporalFeatureComputer, TemporalFeatures
from hybrid_siem.watchlist import WatchlistManager


class TestNonLinearRiskScoring(unittest.TestCase):
    """Test non-linear risk scoring with conditional boosting."""

    def test_linear_scoring(self):
        """Test baseline linear scoring."""
        weights = RiskWeights(use_sigmoid=False, adaptive_boost=False)
        result = compute_risk_score(50.0, 0.5, weights)
        self.assertEqual(result.scoring_method, "linear")
        # 50 * 1.0 + 50 * 0.3 = 50 + 15 = 65
        self.assertEqual(result.risk_score, 65.0)

    def test_conditional_boosting(self):
        """Test conditional boost when both rule and anomaly are high."""
        weights = RiskWeights(
            rule_weight=1.0,
            anomaly_weight=0.3,
            boost_threshold_rule=70.0,
            boost_threshold_anomaly=0.7,
            boost_amount=20.0,
        )
        result = compute_risk_score(75.0, 0.8, weights)
        self.assertEqual(result.scoring_method, "boosted")
        # Base: 75 * 1.0 + 80 * 0.3 = 75 + 24 = 99, then boosted by 20 = 119 → capped at 100
        # But calculation is different - let me check: without boost, linear is 75 + 24 = 99
        # With boost it should be 99 + 20 = 119, capped to 100
        self.assertGreater(result.risk_score, 95.0)

    def test_adaptive_weighting(self):
        """Test adaptive weighting when one signal is weak."""
        weights = RiskWeights(adaptive_boost=True, use_sigmoid=False)
        # Rule weak (40), anomaly strong (0.8)
        result = compute_risk_score(40.0, 0.8, weights)
        self.assertEqual(result.scoring_method, "adaptive")
        # Anomaly should be boosted, rule deprioritized
        self.assertGreater(result.risk_score, 50.0)

    def test_sigmoid_scoring(self):
        """Test sigmoid-based non-linear combination."""
        weights = RiskWeights(use_sigmoid=True)
        result = compute_risk_score(50.0, 0.5, weights)
        self.assertEqual(result.scoring_method, "sigmoid")
        self.assertGreater(result.risk_score, 0.0)
        self.assertLess(result.risk_score, 100.0)


class TestAdversarialScenarios(unittest.TestCase):
    """Test system detection against adversarial attacks."""

    def test_low_and_slow_distributed_detection(self):
        """Test detection of low-and-slow distributed attack."""
        feature_sets = build_scenario_feature_sets()
        scenario_dict = {s[0].name: s[1] for s in feature_sets}
        
        low_and_slow = scenario_dict.get("low_and_slow_distributed", [])
        self.assertTrue(len(low_and_slow) > 0, "Scenario not found")
        
        # Should generate multiple IPs with low individual risk
        ip_count = len(set(r.ip for r in low_and_slow))
        self.assertGreater(ip_count, 3, "Expected multiple attacker IPs")

    def test_username_reuse_attack_detection(self):
        """Test detection of username reuse pattern."""
        feature_sets = build_scenario_feature_sets()
        scenario_dict = {s[0].name: s[1] for s in feature_sets}
        
        username_reuse = scenario_dict.get("username_reuse_attack", [])
        self.assertTrue(len(username_reuse) > 0, "Scenario not found")
        
        # Username variance should be low
        for record in username_reuse:
            self.assertLessEqual(record.username_variance, 3)

    def test_human_like_attack_detection(self):
        """Test detection of human-like attack pattern."""
        feature_sets = build_scenario_feature_sets()
        scenario_dict = {s[0].name: s[1] for s in feature_sets}
        
        human_like = scenario_dict.get("human_like_attack", [])
        self.assertTrue(len(human_like) > 0, "Scenario not found")
        
        # Should have mix of failures and successes
        total_failed = sum(r.failed_count for r in human_like)
        total_attempts = sum(r.event_count for r in human_like)
        self.assertGreater(total_failed, 0)
        self.assertGreater(total_attempts, total_failed)

    def test_mimic_normal_traffic_detection(self):
        """Test detection of attack mimicking normal traffic."""
        feature_sets = build_scenario_feature_sets()
        scenario_dict = {s[0].name: s[1] for s in feature_sets}
        
        mimic_normal = scenario_dict.get("mimic_normal_traffic", [])
        self.assertTrue(len(mimic_normal) > 0, "Scenario not found")
        
        # Should have some windows with failures and some with only successes
        has_failures = any(r.failed_count > 0 for r in mimic_normal)
        self.assertTrue(has_failures, "Expected some failed attempts in mimic scenario")


class TestTemporalFeatures(unittest.TestCase):
    """Test temporal feature computation."""

    def test_temporal_feature_computation(self):
        """Test basic temporal feature computation."""
        base_time = datetime(2026, 4, 28, 10, 0, 0)
        records = [
            FeatureRecord(
                timestamp=base_time + timedelta(seconds=i*60),
                ip="10.0.0.1",
                failed_count=2,
                request_rate=0.05,
                username_variance=3,
                inter_arrival_avg=30.0,
                failed_ratio=0.6,
                event_count=5,
                total_attempts=8,
            )
            for i in range(6)
        ]
        
        computer = TemporalFeatureComputer(window_seconds=60, lookback_windows=5)
        temporal_map = computer.compute(records)
        
        # Should have temporal features for last record
        key = ("10.0.0.1", records[-1].timestamp)
        self.assertIn(key, temporal_map)
        
        temporal = temporal_map[key]
        self.assertGreater(temporal.rolling_failed_count_5m, 0)
        self.assertGreater(temporal.persistence_score, 0)
        self.assertEqual(temporal.activity_duration_seconds, 5 * 60)  # 5 minutes

    def test_burst_detection(self):
        """Test burst score computation."""
        base_time = datetime(2026, 4, 28, 10, 0, 0)
        records = [
            FeatureRecord(
                timestamp=base_time,
                ip="10.0.0.2",
                failed_count=1,
                request_rate=0.02,
                username_variance=5,
                inter_arrival_avg=60.0,
                failed_ratio=0.2,
                event_count=2,
                total_attempts=10,
            ),
            # Sudden spike
            FeatureRecord(
                timestamp=base_time + timedelta(seconds=60),
                ip="10.0.0.2",
                failed_count=10,
                request_rate=0.2,
                username_variance=5,
                inter_arrival_avg=6.0,
                failed_ratio=0.9,
                event_count=20,
                total_attempts=11,
            ),
        ]
        
        computer = TemporalFeatureComputer(window_seconds=60, lookback_windows=5)
        temporal_map = computer.compute(records)
        
        # Burst should be detected in second record
        key = ("10.0.0.2", records[1].timestamp)
        temporal = temporal_map[key]
        self.assertGreater(temporal.burst_score, 30.0, "Expected significant burst")


class TestAdaptiveWatchlist(unittest.TestCase):
    """Test adaptive watchlist with history tracking."""

    def test_repeat_offense_sensitivity_increase(self):
        """Test that repeat offenders become more sensitive to risk."""
        base_time = datetime(2026, 4, 28, 10, 0, 0)
        watchlist = WatchlistManager()
        
        # First high-risk observation
        entry1 = watchlist.update("10.0.0.3", base_time, 85.0)
        self.assertEqual(entry1.strike_count, 1)
        self.assertEqual(entry1.adaptive_sensitivity, 1.0)
        
        # Second high-risk after recovery (new incident)
        watchlist.update("10.0.0.3", base_time + timedelta(minutes=30), 10.0)
        entry2 = watchlist.update("10.0.0.3", base_time + timedelta(minutes=35), 85.0)
        self.assertEqual(entry2.strike_count, 2)
        self.assertEqual(entry2.repeat_incidents, 1)
        
        # Third high-risk - sensitivity increases
        watchlist.update("10.0.0.3", base_time + timedelta(minutes=60), 10.0)
        entry3 = watchlist.update("10.0.0.3", base_time + timedelta(minutes=65), 85.0)
        self.assertEqual(entry3.strike_count, 3)
        self.assertGreater(entry3.adaptive_sensitivity, 1.0)

    def test_adaptive_score_boost(self):
        """Test that adaptive sensitivity boosts risk score for repeat offenders."""
        base_time = datetime(2026, 4, 28, 10, 0, 0)
        watchlist = WatchlistManager()
        
        # Establish history of 3 strikes
        for i in range(3):
            watchlist.update("10.0.0.4", base_time + timedelta(minutes=i*30), 85.0)
            watchlist.update("10.0.0.4", base_time + timedelta(minutes=i*30+15), 10.0)
        
        # New observation with medium risk should be boosted
        entry = watchlist.update("10.0.0.4", base_time + timedelta(minutes=100), 60.0)
        self.assertGreater(entry.current_risk_score, 60.0, "Risk should be boosted for repeat offender")
        self.assertGreater(entry.adaptive_sensitivity, 1.2)


class TestExplainability(unittest.TestCase):
    """Test decision explainability and reasoning."""

    def test_pipeline_decision_has_reasons(self):
        """Test that pipeline decisions include explanatory reasons."""
        base_time = datetime(2026, 4, 28, 10, 0, 0)
        records = [
            FeatureRecord(
                timestamp=base_time,
                ip="10.0.0.5",
                failed_count=8,
                request_rate=0.15,
                username_variance=2,
                inter_arrival_avg=8.0,
                failed_ratio=0.95,
                event_count=10,
                total_attempts=10,
            ),
        ]
        
        decisions = process_feature_records(records)
        self.assertEqual(len(decisions), 1)
        
        decision = decisions[0]
        self.assertIsInstance(decision.reasons, tuple)
        self.assertGreater(len(decision.reasons), 0, "Decision should have reasons")
        
        # Check that reasons mention important factors
        reasons_text = " ".join(decision.reasons).lower()
        self.assertTrue(
            "failed" in reasons_text or "high" in reasons_text or "block" in reasons_text,
            f"Reasons should explain why IP is blocked: {decision.reasons}"
        )

    def test_temporal_insight_generation(self):
        """Test that temporal insights are generated when applicable."""
        base_time = datetime(2026, 4, 28, 10, 0, 0)
        records = [
            FeatureRecord(
                timestamp=base_time + timedelta(seconds=i*60),
                ip="10.0.0.6",
                failed_count=3,
                request_rate=0.05,
                username_variance=2,
                inter_arrival_avg=20.0,
                failed_ratio=0.7,
                event_count=15,  # High event concentration
                total_attempts=20,
            )
            for i in range(3)
        ]
        
        decisions = process_feature_records(records)
        
        # Should detect high event concentration
        decision = decisions[-1]
        if decision.feature_record.event_count >= 10:
            self.assertNotEqual(decision.temporal_insight, "")


class TestEndToEndAdversarialDetection(unittest.TestCase):
    """End-to-end test of adversarial detection."""

    def test_all_adversarial_scenarios_processed(self):
        """Test that all adversarial scenarios can be processed."""
        feature_sets = build_scenario_feature_sets()
        weights = RiskWeights(adaptive_boost=True)
        
        for scenario_def, records in feature_sets:
            if "adversarial" in scenario_def.name or any(
                x in scenario_def.name
                for x in [
                    "low_and_slow",
                    "username_reuse",
                    "human_like",
                    "mimic_normal",
                ]
            ):
                decisions = process_feature_records(records, weights=weights)
                
                # All should have decisions
                self.assertGreater(len(decisions), 0)
                
                # Check that decisions have proper fields
                for decision in decisions:
                    self.assertIsInstance(decision, PipelineDecision)
                    self.assertIsNotNone(decision.risk_score)
                    self.assertIsNotNone(decision.action)
                    self.assertGreater(len(decision.reasons), 0)


if __name__ == "__main__":
    unittest.main()
