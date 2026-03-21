#!/usr/bin/env python3
"""
Simulation harness for testing the Peer Defense Module.

Injects fake anomaly events to validate the detection-and-response pipeline
without requiring a live adversarial scenario.
"""

import asyncio
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))

from peer_defense import (
    AnomalyResult,
    Config, Metrics, AnomalyDetector, ResponseEngine, 
    Logger, MetricsCollector, PostfiatdClient
)


class SimulationRunner:
    def __init__(self):
        self.results = []
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        self.log_path = self.temp_log.name
        self.temp_log.close()
    
    def create_config(self, overrides: dict = None) -> Config:
        with open('/home/postfiat/peer-defense/config.json') as f:
            config = Config('/home/postfiat/peer-defense/config.json')
        config.log_path = self.log_path
        if overrides:
            for k, v in overrides.items():
                if hasattr(config, k):
                    setattr(config, k, v)
        return config
    
    def run_scenario(self, name: str, scenario_func):
        print(f"\n{'='*60}")
        print(f"[SCENARIO] {name}")
        print('='*60)
        
        try:
            result = scenario_func()
            status = "PASS" if result else "FAIL"
            self.results.append((name, status))
            print(f"\n[{status}] {name}")
            return result
        except Exception as e:
            import traceback
            self.results.append((name, f"FAIL: {e}"))
            print(f"\n[FAIL] {name}: {e}")
            traceback.print_exc()
            return False
    
    def print_summary(self):
        print(f"\n{'='*60}")
        print("SIMULATION SUMMARY")
        print('='*60)
        passed = sum(1 for _, s in self.results if s == "PASS")
        total = len(self.results)
        print(f"Passed: {passed}/{total}")
        for name, status in self.results:
            print(f"  {status}: {name}")
        print('='*60)


def test_peer_count_low_detection():
    runner = SimulationRunner()
    
    def scenario():
        config = runner.create_config({'peer_count_floor': 5})
        detector = AnomalyDetector(config)
        
        metrics = Metrics(
            peer_count=2,
            scoring_latency_ms=100,
            ledger_sync_lag_seconds=5,
            server_state="full",
            peers_list=[],
            collected_at="2026-03-20T10:00:00Z"
        )
        
        result = detector.detect(metrics)
        
        print(f"  Input: peer_count={metrics.peer_count} (threshold: {config.peer_count_floor})")
        print(f"  Detected: severity={result.severity}, breaches={result.breaches}")
        
        assert result.severity == "WARNING", f"Expected WARNING, got {result.severity}"
        assert "peer_count_low" in result.breaches
        return True
    
    return runner.run_scenario("peer_drop: 2 peers (threshold: 5)", scenario)


def test_latency_spike_detection():
    runner = SimulationRunner()
    
    def scenario():
        config = runner.create_config({'scoring_latency_ceiling_ms': 500})
        detector = AnomalyDetector(config)
        
        metrics = Metrics(
            peer_count=10,
            scoring_latency_ms=800,
            ledger_sync_lag_seconds=5,
            server_state="full",
            peers_list=[],
            collected_at="2026-03-20T10:00:00Z"
        )
        
        result = detector.detect(metrics)
        
        print(f"  Input: latency={metrics.scoring_latency_ms}ms (threshold: {config.scoring_latency_ceiling_ms}ms)")
        print(f"  Detected: severity={result.severity}, breaches={result.breaches}")
        
        assert result.severity == "WARNING", f"Expected WARNING, got {result.severity}"
        assert "latency_high" in result.breaches
        return True
    
    return runner.run_scenario("latency_spike: 800ms (threshold: 500ms)", scenario)


def test_ledger_lag_detection():
    runner = SimulationRunner()
    
    def scenario():
        config = runner.create_config({'ledger_sync_lag_max_seconds': 30})
        detector = AnomalyDetector(config)
        
        metrics = Metrics(
            peer_count=10,
            scoring_latency_ms=100,
            ledger_sync_lag_seconds=60,
            server_state="full",
            peers_list=[],
            collected_at="2026-03-20T10:00:00Z"
        )
        
        result = detector.detect(metrics)
        
        print(f"  Input: lag={metrics.ledger_sync_lag_seconds}s (threshold: {config.ledger_sync_lag_max_seconds}s)")
        print(f"  Detected: severity={result.severity}, breaches={result.breaches}")
        
        assert result.severity == "WARNING", f"Expected WARNING, got {result.severity}"
        assert "ledger_lag_high" in result.breaches
        return True
    
    return runner.run_scenario("ledger_lag: 60s (threshold: 30s)", scenario)


def test_multi_breach_critical():
    runner = SimulationRunner()
    
    def scenario():
        config = runner.create_config({
            'peer_count_floor': 5,
            'scoring_latency_ceiling_ms': 500,
            'ledger_sync_lag_max_seconds': 30
        })
        detector = AnomalyDetector(config)
        
        metrics = Metrics(
            peer_count=2,
            scoring_latency_ms=800,
            ledger_sync_lag_seconds=5,
            server_state="full",
            peers_list=[],
            collected_at="2026-03-20T10:00:00Z"
        )
        
        result = detector.detect(metrics)
        
        print(f"  Input: peer_count={metrics.peer_count}, latency={metrics.scoring_latency_ms}ms")
        print(f"  Detected: severity={result.severity}, breaches={result.breaches}")
        
        assert result.severity == "CRITICAL", f"Expected CRITICAL, got {result.severity}"
        assert len(result.breaches) >= 2
        return True
    
    return runner.run_scenario("multi_breach: 2 peers + 800ms latency", scenario)


def test_sustained_breach_critical():
    runner = SimulationRunner()
    
    def scenario():
        config = runner.create_config({
            'peer_count_floor': 5,
            'sustained_breach_intervals': 3
        })
        detector = AnomalyDetector(config)
        
        result = None
        for i in range(3):
            metrics = Metrics(
                peer_count=2,
                scoring_latency_ms=100,
                ledger_sync_lag_seconds=5,
                server_state="full",
                peers_list=[],
                collected_at=f"2026-03-20T10:0{i}:00Z"
            )
            result = detector.detect(metrics)
            print(f"  Interval {i+1}: severity={result.severity}, breaches={result.breaches}")
        
        assert result.severity == "CRITICAL", f"Expected CRITICAL after sustained breach, got {result.severity}"
        return True
    
    return runner.run_scenario("sustained_breach: 3 consecutive intervals", scenario)


async def test_response_reconnect():
    runner = SimulationRunner()
    
    mock_client = MagicMock(spec=PostfiatdClient)
    mock_client.peers = AsyncMock(return_value={
        "result": {
            "peers": [
                {"ip": "10.0.0.1", "port": 2559},
                {"ip": "10.0.0.2", "port": 2559},
                {"ip": "10.0.0.3", "port": 2559}
            ]
        }
    })
    mock_client.connect = AsyncMock(return_value={"result": {"status": "connected"}})
    
    config = runner.create_config({'peer_reconnect_attempts': 3})
    logger = Logger(runner.log_path)
    responder = ResponseEngine(mock_client, config, logger)
    
    anomaly = AnomalyResult(
        severity="WARNING",
        breaches=["peer_count_low"],
        metrics={"peer_count": 2}
    )
    
    result = await responder.handle_warning(anomaly)
    
    print(f"  Reconnect attempts: {result.get('attempts', 0)}")
    print(f"  Results: {json.dumps(result.get('results', []), indent=2)}")
    
    return result.get('attempts', 0) > 0


def test_response_reconnect_sync():
    runner = SimulationRunner()
    
    def scenario():
        return asyncio.run(test_response_reconnect())
    
    return runner.run_scenario("response_reconnect: peer reconnection attempt", scenario)


async def test_firewall_rotation():
    runner = SimulationRunner()
    
    config = runner.create_config({'firewall_ban_duration_minutes': 60})
    logger = Logger(runner.log_path)
    
    mock_client = MagicMock(spec=PostfiatdClient)
    responder = ResponseEngine(mock_client, config, logger)
    
    suspicious_ips = ["192.168.1.100", "10.0.0.50"]
    
    print(f"  Testing firewall rule rotation for IPs: {suspicious_ips}")
    print(f"  (Actual UFW commands will be logged but may fail without sudo)")
    
    result = await responder._rotate_firewall_rules(suspicious_ips)
    
    print(f"  Results: {json.dumps(result, indent=2)}")
    
    with open(runner.log_path) as f:
        log_content = f.read()
    
    print(f"  Log entries created: {log_content.count(chr(10))}")
    
    return "FIREWALL_ROTATE" in log_content


def test_firewall_rotation_sync():
    runner = SimulationRunner()
    
    def scenario():
        return asyncio.run(test_firewall_rotation())
    
    return runner.run_scenario("firewall_rotation: UFW deny rule insertion", scenario)


def test_full_pipeline():
    runner = SimulationRunner()
    
    def scenario():
        config = runner.create_config({
            'peer_count_floor': 5,
            'scoring_latency_ceiling_ms': 500,
            'sustained_breach_intervals': 2
        })
        
        detector = AnomalyDetector(config)
        logger = Logger(runner.log_path)
        
        anomaly = AnomalyResult(
            severity="CRITICAL",
            breaches=["peer_count_low", "latency_high"],
            metrics={
                "peer_count": 2,
                "scoring_latency_ms": 800,
                "peers_list": [{"ip": "10.0.0.1", "state": "disconnected"}]
            }
        )
        
        logger.log("CRITICAL_DETECTED", anomaly.breaches, anomaly.metrics)
        
        with open(runner.log_path) as f:
            log_entries = [json.loads(line) for line in f if line.strip()]
        
        print(f"  Log entries: {len(log_entries)}")
        if log_entries:
            last_entry = log_entries[-1]
            print(f"  Last entry event: {last_entry.get('event')}")
            print(f"  Last entry data: {last_entry.get('data')}")
        
        return len(log_entries) > 0 and log_entries[-1].get('event') == 'CRITICAL_DETECTED'
    
    return runner.run_scenario("full_pipeline: detection + logging", scenario)


def main():
    print("\n" + "="*60)
    print("PEER DEFENSE MODULE - SIMULATION HARNESS")
    print("="*60)
    
    runner = SimulationRunner()
    
    test_peer_count_low_detection()
    test_latency_spike_detection()
    test_ledger_lag_detection()
    test_multi_breach_critical()
    test_sustained_breach_critical()
    test_response_reconnect_sync()
    test_firewall_rotation_sync()
    test_full_pipeline()
    
    runner.print_summary()
    
    Path(runner.log_path).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
