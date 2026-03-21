#!/usr/bin/env python3
"""
Autonomous Peer Reconnection Module for Validator Defense

Monitors validator peer connections, AI scoring logs, and ledger sync status.
Detects anomalies and triggers automatic responses:
- WARNING: Attempt peer reconnection
- CRITICAL: Rotate firewall rules + force fresh peer discovery
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp


@dataclass
class Metrics:
    peer_count: int
    scoring_latency_ms: int
    ledger_sync_lag_seconds: int
    server_state: str
    peers_list: list
    collected_at: str


@dataclass
class AnomalyResult:
    severity: str
    breaches: list
    metrics: dict


class Config:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            data = json.load(f)
        
        self.peer_count_floor = data['thresholds']['peer_count_floor']
        self.scoring_latency_ceiling_ms = data['thresholds']['scoring_latency_ceiling_ms']
        self.ledger_sync_lag_max_seconds = data['thresholds']['ledger_sync_lag_max_seconds']
        self.sustained_breach_intervals = data['thresholds']['sustained_breach_intervals']
        
        self.poll_interval_seconds = data['monitoring']['poll_interval_seconds']
        self.log_path = data['monitoring']['log_path']
        
        self.peer_reconnect_attempts = data['response']['peer_reconnect_attempts']
        self.firewall_ban_duration_minutes = data['response']['firewall_ban_duration_minutes']
        
        self.postfiatd_host = data['postfiatd']['host']
        self.postfiatd_port = data['postfiatd']['port']


class PostfiatdClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
    

    async def server_info(self) -> dict:
        return await self.request("server_info", [{}])

    async def peers(self) -> dict:
        return await self.request("peers", [])

    async def connect(self, ip: str, port: int = 2559) -> dict:
        return await self.request("connect", [{"ip": ip, "port": port}])
    async def request(self, method: str, params: list = None) -> dict:
        payload = {"method": method, "params": params or []}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    text = await resp.text()
                    if text == "Forbidden" or resp.status == 403:
                        return {"error": "Forbidden", "status": "error"}
                    return json.loads(text)
        except asyncio.TimeoutError:
            return {"error": "Request timeout", "status": "error"}
        except Exception as e:
            return {"error": str(e), "status": "error"}


class MetricsCollector:
    def __init__(self, client: PostfiatdClient):
        self.client = client
    
    async def collect(self) -> Metrics:
        try:
            server_info = await self.client.server_info()
            
            if server_info.get("status") == "error":
                raise ValueError(f"server_info error: {server_info.get('error')}")
            
            info = server_info.get('result', {}).get('info', {})
            
            if not info:
                raise ValueError(f"Invalid server_info response: {server_info}")
            
            peer_count = info.get('peers', 0)
            ledger_age = info.get('validated_ledger', {}).get('age', 0)
            server_state = info.get('server_state', 'unknown')
            
            scoring_latency_ms = await self._measure_scoring_latency()
            
            peers_list = []
            try:
                peers_resp = await self.client.peers()
                peers_list = peers_resp.get('result', {}).get('peers', [])
            except:
                pass
            
            return Metrics(
                peer_count=peer_count,
                scoring_latency_ms=scoring_latency_ms,
                ledger_sync_lag_seconds=ledger_age,
                server_state=server_state,
                peers_list=peers_list,
                collected_at=datetime.now(timezone.utc).isoformat()
            )
        except Exception as e:
            print(f"Error collecting metrics: {e}")
            return Metrics(
                peer_count=0,
                scoring_latency_ms=9999,
                ledger_sync_lag_seconds=9999,
                server_state="error",
                peers_list=[],
                collected_at=datetime.now(timezone.utc).isoformat()
            )
    
    async def _measure_scoring_latency(self) -> int:
        import time
        start = time.time()
        try:
            await self.client.server_info()
            return int((time.time() - start) * 1000)
        except:
            return 9999


class AnomalyDetector:
    def __init__(self, config: Config):
        self.config = config
        self.history: deque = deque(maxlen=config.sustained_breach_intervals + 1)
    
    def detect(self, metrics: Metrics) -> AnomalyResult:
        breaches = []
        
        if metrics.peer_count < self.config.peer_count_floor:
            breaches.append("peer_count_low")
        
        if metrics.scoring_latency_ms > self.config.scoring_latency_ceiling_ms:
            breaches.append("latency_high")
        
        if metrics.ledger_sync_lag_seconds > self.config.ledger_sync_lag_max_seconds:
            breaches.append("ledger_lag_high")
        
        self.history.append(breaches)
        
        sustained = self._check_sustained_breach()
        
        if sustained or len(breaches) >= 2:
            severity = "CRITICAL"
        elif len(breaches) >= 1:
            severity = "WARNING"
        else:
            severity = "OK"
        
        return AnomalyResult(
            severity=severity,
            breaches=breaches,
            metrics=asdict(metrics)
        )
    
    def _check_sustained_breach(self) -> bool:
        if len(self.history) < self.config.sustained_breach_intervals:
            return False
        
        recent = list(self.history)[-self.config.sustained_breach_intervals:]
        if all(len(b) > 0 for b in recent):
            common = set(recent[0])
            for b in recent[1:]:
                common &= set(b)
            return len(common) > 0
        return False


class ResponseEngine:
    def __init__(self, client: PostfiatdClient, config: Config, logger):
        self.client = client
        self.config = config
        self.logger = logger
        self._shutdown_event = None
    
    def set_shutdown_event(self, event):
        self._shutdown_event = event
    
    async def handle_warning(self, anomaly: AnomalyResult) -> dict:
        self.logger.log("WARNING_DETECTED", anomaly.breaches, anomaly.metrics)
        
        try:
            result = await self._attempt_peer_reconnect()
            return result
        except Exception as e:
            self.logger.log("WARNING_RESPONSE_FAILED", {"error": str(e), "breaches": anomaly.breaches})
            return {"error": str(e), "attempts": 0}
    
    async def handle_critical(self, anomaly: AnomalyResult) -> dict:
        self.logger.log("CRITICAL_DETECTED", anomaly.breaches, anomaly.metrics)
        
        results = {"firewall": None, "reconnect": None}
        
        try:
            suspicious_ips = self._identify_suspicious_ips(anomaly)
            results["firewall"] = await self._rotate_firewall_rules(suspicious_ips)
        except Exception as e:
            self.logger.log("CRITICAL_FIREWALL_FAILED", {"error": str(e)})
            results["firewall"] = {"error": str(e)}
        
        try:
            results["reconnect"] = await self._attempt_peer_reconnect()
        except Exception as e:
            self.logger.log("CRITICAL_RECONNECT_FAILED", {"error": str(e)})
            results["reconnect"] = {"error": str(e)}
        
        return results
    
    async def _attempt_peer_reconnect(self) -> dict:
        results = []
        attempts = self.config.peer_reconnect_attempts
        
        self.logger.log("PEER_RECONNECT_ATTEMPT", {"max_attempts": attempts})
        
        for attempt in range(attempts):
            try:
                connect_result = await self.client.connect("127.0.0.1", 2559)
                results.append({"attempt": attempt + 1, "status": "attempted", "result": connect_result})
                await asyncio.sleep(1)
            except Exception as e:
                self.logger.log("PEER_RECONNECT_RETRY", {"attempt": attempt + 1, "error": str(e)})
                results.append({"attempt": attempt + 1, "status": "failed", "error": str(e)})
        
        self.logger.log("PEER_RECONNECT", {"attempts": len(results), "results": results})
        return {"attempts": len(results), "results": results}
    
    def _identify_suspicious_ips(self, anomaly: AnomalyResult) -> list:
        suspicious = []
        peers = anomaly.metrics.get('peers_list', [])
        
        for peer in peers:
            if peer.get('state') in ['disconnecting', 'disconnected']:
                suspicious.append(peer.get('ip'))
        
        return suspicious[:5]
    
    async def _rotate_firewall_rules(self, suspicious_ips: list) -> dict:
        results = []
        
        if not suspicious_ips:
            self.logger.log("FIREWALL_ROTATE", {"denied_ips": [], "reason": "no_suspicious_ips"})
            return {"denied": 0, "results": results}
        
        for ip in suspicious_ips:
            if not ip:
                continue
            try:
                result = subprocess.run(
                    ["sudo", "ufw", "insert", "1", "deny", "from", ip],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    results.append({"ip": ip, "action": "denied"})
                else:
                    results.append({"ip": ip, "action": "failed", "error": result.stderr})
            except Exception as e:
                results.append({"ip": ip, "action": "error", "error": str(e)})
        
        self.logger.log("FIREWALL_ROTATE", {"denied_ips": results})
        return {"denied": len([r for r in results if r.get("action") == "denied"]), "results": results}


class Logger:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
    
    def log(self, event: str, data: dict, metrics: dict = None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data
        }
        if metrics:
            entry["metrics"] = metrics
        
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Failed to write log: {e}")
        
        print(f"[{entry['timestamp']}] {event}: {data}")


class MonitorLoop:
    def __init__(self, config: Config, test_mode: bool = False):
        self.config = config
        self.test_mode = test_mode
        self.client = PostfiatdClient(config.postfiatd_host, config.postfiatd_port)
        self.collector = MetricsCollector(self.client)
        self.detector = AnomalyDetector(config)
        self.logger = Logger(config.log_path)
        self.responder = ResponseEngine(self.client, config, self.logger)
        self.running = False
        self._shutdown_handlers_installed = False
    
    def _install_signal_handlers(self):
        if self._shutdown_handlers_installed:
            return
        
        def handle_signal(signum, frame):
            self.logger.log("SIGNAL_RECEIVED", {"signal": signum})
            self.running = False
        
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        self._shutdown_handlers_installed = True
    
    async def run(self):
        self.running = True
        self._install_signal_handlers()
        self.logger.log("MONITOR_STARTED", {
            "config": str(self.config.__dict__),
            "test_mode": self.test_mode
        })
        
        while self.running:
            try:
                metrics = await self.collector.collect()
                anomaly = self.detector.detect(metrics)
                
                self.logger.log("POLL", {
                    "severity": anomaly.severity, 
                    "breaches": anomaly.breaches
                }, anomaly.metrics)
                
                if anomaly.severity == "WARNING":
                    await self.responder.handle_warning(anomaly)
                elif anomaly.severity == "CRITICAL":
                    await self.responder.handle_critical(anomaly)
                
            except asyncio.CancelledError:
                self.logger.log("MONITOR_CANCELLED", {"reason": "async_cancelled"})
                break
            except Exception as e:
                self.logger.log("POLL_ERROR", {
                    "error": str(e),
                    "error_type": type(e).__name__
                })
                if self.test_mode:
                    raise
            
            if self.test_mode:
                self.logger.log("MONITOR_TEST_MODE_EXIT", {"reason": "single_poll"})
                break
            
            await asyncio.sleep(self.config.poll_interval_seconds)
        
        self.logger.log("MONITOR_STOPPED", {"reason": "normal"})
    
    def stop(self):
        self.running = False
        self.logger.log("MONITOR_STOP_REQUESTED", {"reason": "external"})


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Autonomous Peer Reconnection Module")
    parser.add_argument("--config", default="/home/postfiat/peer-defense/config.json", help="Path to config file")
    parser.add_argument("--test", action="store_true", help="Run in test mode (single poll)")
    parser.add_argument("--once", action="store_true", help="Run single poll and exit")
    args = parser.parse_args()
    
    config_path = os.getenv("CONFIG_PATH", args.config)
    
    if os.path.exists(config_path):
        config = Config(config_path)
    else:
        print(f"Config file not found: {config_path}")
        sys.exit(1)
    
    monitor = MonitorLoop(config, test_mode=args.test or args.once)
    
    try:
        asyncio.run(monitor.run())
    except KeyboardInterrupt:
        monitor.logger.log("MONITOR_STOPPED", {"reason": "keyboard_interrupt"})


if __name__ == "__main__":
    main()
