# PostFiat Peer Defense

Autonomous peer reconnection and defense module for PostFiat validators. Monitors peer connections, AI scoring latency, and ledger sync status, triggering automatic responses to anomalies.

## Features

- Continuous peer health monitoring
- AI scoring latency tracking
- Ledger sync lag detection
- Automatic peer reconnection on warnings
- Firewall rule rotation on critical breaches
- Configurable thresholds and response actions

## Requirements

- Python 3.9+
- aiohttp
- Access to postfiatd node

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Edit `config.json`:

```json
{
  "thresholds": {
    "peer_count_floor": 5,
    "scoring_latency_ceiling_ms": 500,
    "ledger_sync_lag_max_seconds": 30,
    "sustained_breach_intervals": 3
  },
  "monitoring": {
    "poll_interval_seconds": 30,
    "log_path": "/path/to/defense.log"
  },
  "response": {
    "peer_reconnect_attempts": 3,
    "firewall_ban_duration_minutes": 60
  },
  "postfiatd": {
    "host": "127.0.0.1",
    "port": 5005
  }
}
```

## Usage

```bash
python peer_defense.py
```

## How It Works

1. **Polls postfiatd** for server_info and peer data
2. **Evaluates metrics** against configured thresholds
3. **Tracks breach history** over multiple intervals
4. **Triggers responses**:
   - WARNING: Attempts peer reconnection
   - CRITICAL: Rotates firewall rules + forces fresh peer discovery

## Thresholds

| Metric | Default Threshold |
|--------|------------------|
| Peer count | >= 5 |
| AI scoring latency | <= 500ms |
| Ledger sync lag | <= 30s |

## License

MIT
