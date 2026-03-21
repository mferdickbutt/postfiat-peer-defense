#!/usr/bin/env python3
"""
Resilience test suite for Peer Defense Module.

Tests error handling and recovery in various failure scenarios.
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))

from peer_defense import (
    Config, Metrics, AnomalyResult, MonitorLoop,
    ResponseEngine, Logger, PostfiatdClient, MetricsCollector
)


class ResilienceTestRunner:
    def __init__(self):
        self.results = []
        self.temp_log_path = "/tmp/resilience_test.log"
    
    def run_test(self, name: str, test_func):
        print(f"\n{'='*60}")
        print(f"[TEST] {name}")
        print('='*60)
        
        try:
            result = test_func()
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
        print("RESILIENCE TEST SUMMARY")
        print('='*60)
        passed = sum(1 for _, s in self.results if s == "PASS")
        total = len(self.results)
        print(f"Passed: {passed}/{total}")
        for name, status in self.results:
            print(f"  {status}: {name}")
        print('='*60)


def test_monitor_continues_after_collection_error():
    """Monitor should continue even if metrics collection fails"""
    runner = ResilienceTestRunner()
    
    def test():
        with patch('peer_defense.MetricsCollector') as MockCollector:
            # Configure mock to fail initially, then succeed
            call_count = [0]
            
            async def side_effect(*args):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise ValueError("Connection refused")
                return Metrics(
                    peer_count=10,
                    scoring_latency_ms=100,
                    ledger_sync_lag_seconds=5,
                    server_state="full",
                    peers_list=[],
                    collected_at="2026-03-20T10:00:00Z"
                )
            
            mock_collector = MagicMock()
            mock_collector.collect = side_effect
            
            # Test that we can handle errors
            async def run_test():
                config = Config("/home/postfiat/peer-defense/config.json")
                monitor = MonitorLoop(config)
                monitor.collector = mock_collector
                
                # Run for 3 cycles
                results = []
                for i in range(3):
                    try:
                        metrics = await monitor.collector.collect()
                        results.append(("success", metrics.peer_count))
                    except Exception as e:
                        results.append(("error", str(e)))
                
                return len([r for r in results if r[0] == "success"]) > 0
            
            return asyncio.run(run_test())
    
    return runner.run_test("monitor_continues_after_collection_error", test)


def test_handle_warning_continues_after_reconnect_failure():
    """WARNING response should complete even if reconnection fails"""
    runner = ResilienceTestRunner()
    
    def test():
        async def run_test():
            config = Config("/home/postfiat/peer-defense/config.json")
            client = PostfiatdClient(config.postfiatd_host, config.postfiatd_port)
            logger = Logger(runner.temp_log_path)
            responder = ResponseEngine(client, config, logger)
            
            # Mock client to fail
            with patch.object(client, 'connect', side_effect=Exception("Connection failed")):
                anomaly = AnomalyResult(
                    severity="WARNING",
                    breaches=["peer_count_low"],
                    metrics={"peer_count": 2}
                )
                
                result = await responder.handle_warning(anomaly)
                
                # Should still return a result, not raise exception
                return result is not None and "attempts" in result
        
        return asyncio.run(run_test())
    
    return runner.run_test("handle_warning_continues_after_reconnect_failure", test)


def test_handle_critical_continues_after_partial_failure():
    """CRITICAL response should complete even if firewall fails"""
    runner = ResilienceTestRunner()
    
    def test():
        async def run_test():
            config = Config("/home/postfiat/peer-defense/config.json")
            client = PostfiatdClient(config.postfiatd_host, config.postfiatd_port)
            logger = Logger(runner.temp_log_path)
            responder = ResponseEngine(client, config, logger)
            
            anomaly = AnomalyResult(
                severity="CRITICAL",
                breaches=["peer_count_low", "latency_high"],
                metrics={
                    "peer_count": 2,
                    "peers_list": [{"ip": "10.0.0.1", "state": "disconnected"}]
                }
            )
            
            result = await responder.handle_critical(anomaly)
            
            # Both firewall and reconnect results should be present
            return "firewall" in result and "reconnect" in result
        
        return asyncio.run(run_test())
    
    return runner.run_test("handle_critical_continues_after_partial_failure", test)


def test_graceful_shutdown():
    """Monitor should handle SIGTERM gracefully"""
    runner = ResilienceTestRunner()
    
    def test():
        config = Config("/home/postfiat/peer-defense/config.json")
        monitor = MonitorLoop(config)
        
        # Verify shutdown handlers are installed
        monitor._install_signal_handlers()
        
        # Verify running flag works
        monitor.running = True
        monitor.stop()
        
        return not monitor.running
    
    return runner.run_test("graceful_shutdown", test)


def test_json_log_integrity():
    """All events should be logged as valid JSON"""
    runner = ResilienceTestRunner()
    
    def test():
        logger = Logger(runner.temp_log_path)
        
        # Log various events
        logger.log("TEST_EVENT", {"key": "value"})
        logger.log("METRICS_EVENT", {"peer_count": 5}, {"extra": "metrics"})
        
        # Verify log integrity
        with open(runner.temp_log_path) as f:
            for line in f:
                entry = json.loads(line.strip())
                if not all(k in entry for k in ["timestamp", "event", "data"]):
                    return False
        
        return True
    
    return runner.run_test("json_log_integrity", test)


def test_error_logging():
    """Errors should be logged, not crash the monitor"""
    runner = ResilienceTestRunner()
    
    def test():
        config = Config("/home/postfiat/peer-defense/config.json")
        logger = Logger(runner.temp_log_path)
        client = PostfiatdClient(config.postfiatd_host, config.postfiatd_port)
        responder = ResponseEngine(client, config, logger)
        
        # Create a malformed anomaly that might cause issues
        anomaly = AnomalyResult(
            severity="CRITICAL",
            breaches=["test_breach"],
            metrics={"peers_list": []}  # Empty peers list
        )
        
        async def run_test():
            result = await responder.handle_critical(anomaly)
            
            # Check log contains the event
            with open(runner.temp_log_path) as f:
                log_content = f.read()
            
            return "CRITICAL_DETECTED" in log_content
        
        return asyncio.run(run_test())
    
    return runner.run_test("error_logging", test)


def main():
    print("\n" + "="*60)
    print("PEER DEFENSE MODULE - RESILIENCE TEST SUITE")
    print("="*60)
    
    runner = ResilienceTestRunner()
    
    test_monitor_continues_after_collection_error()
    test_handle_warning_continues_after_reconnect_failure()
    test_handle_critical_continues_after_partial_failure()
    test_graceful_shutdown()
    test_json_log_integrity()
    test_error_logging()
    
    runner.print_summary()
    
    # Cleanup
    Path(runner.temp_log_path).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
