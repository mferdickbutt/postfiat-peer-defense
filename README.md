# PostFiat Peer Defense

Autonomous validator defense and governance toolkit for PostFiat validators.
The repo now includes two operational paths:

- `peer_defense.py` for peer reconnection and anomaly response
- `unl_voting.py` for UNL peer health voting transactions on XRPL

## Features

- Continuous peer health monitoring
- AI scoring latency tracking
- Ledger sync lag detection
- Automatic peer reconnection on warnings
- Firewall rule rotation on critical breaches
- UNL peer health vote construction with signed XRPL memos
- Dry-run or on-ledger submission flow for validator governance votes

## Requirements

- Python 3.9+
- `aiohttp`
- `xrpl-py`
- `PyNaCl`
- Access to `postfiatd`
- Validator key material in `validator-health-telemetry/keys/validator-keys.json`

## Installation

```bash
pip install -r requirements.txt
```

On Debian or Ubuntu images with PEP 668 enabled, the simplest operator-friendly
install path is:

```bash
python3 -m pip install --user --break-system-packages -r requirements.txt
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
    "log_path": "/home/postfiat/peer-defense/logs/defense.log"
  },
  "response": {
    "peer_reconnect_attempts": 3,
    "firewall_ban_duration_minutes": 60
  },
  "postfiatd": {
    "host": "127.0.0.1",
    "port": 5005
  },
  "unl_voting": {
    "uptime_min_pct": 0.98,
    "latency_max_ms": 500,
    "consensus_min_pct": 0.95,
    "last_seen_max_age_seconds": 900,
    "xrpl_rpc_url": "http://127.0.0.1:5005",
    "validator_keys_path": "/home/postfiat/validator-health-telemetry/keys/validator-keys.json",
    "fee_payer_seed_env": "XRPL_FEE_PAYER_SEED",
    "dry_run_default": true
  }
}
```

## Peer Defense Usage

```bash
python3 peer_defense.py
```

## UNL Voting Usage

Dry-run against a real log file:

```bash
python3 unl_voting.py --input /path/to/peer_scores.jsonl
```

Dry-run against the bundled sample dataset:

```bash
python3 unl_voting.py --simulate
```

Filter to a single peer:

```bash
python3 unl_voting.py --input /path/to/peer_scores.jsonl --peer nHExamplePeerKey
```

Submit on-ledger with a funded fee-payer wallet:

```bash
export XRPL_FEE_PAYER_SEED=sXXXXXXXXXXXX
python3 unl_voting.py --input /path/to/peer_scores.jsonl --submit
```

If `XRPL_FEE_PAYER_SEED` is not set, `unl_voting.py` will stay in dry-run mode
and use a generated ephemeral wallet only for local transaction signing.

## UNL Voting Input Schema

`unl_voting.py` accepts either JSONL or a JSON array. Each peer record must
normalize to:

```json
{
  "validator_public_key": "nHPeerValidatorPublicKey",
  "uptime_pct": 99.4,
  "scoring_latency_ms": 85,
  "consensus_participation_pct": 99.2,
  "last_seen_utc": "2026-03-24T00:00:00Z",
  "collected_at": "2026-03-24T00:00:05Z"
}
```

Percentage fields may be provided either as fractions (`0.994`) or percentages
(`99.4`). Invalid records are skipped with a readable warning in terminal output.

## UNL Vote Memo Schema

The XRPL memo payload uses schema `postfiat.unl_vote.v1` and includes:

- `schema`
- `peer_validator_public_key`
- `verdict`
- `evaluated_at`
- `breaches`
- `voter_validator_public_key`
- `metrics_digest_sha256`
- `validator_signature`

The memo is encoded as minified JSON in `MemoData`, with:

- `MemoType = postfiat.unl_vote.v1`
- `MemoFormat = application/json`

Votes are transported in a memo-carrying `AccountSet` transaction so the
validator can publish governance data on-ledger without moving XRP. XRPL's
reference docs note that an `AccountSet` with no account-setting changes still
validly consumes the transaction fee and can carry common fields such as memos.

## Thresholds

### Defense thresholds

| Metric | Default Threshold |
|--------|------------------|
| Peer count | >= 5 |
| AI scoring latency | <= 500ms |
| Ledger sync lag | <= 30s |

### Voting thresholds

| Metric | Default Threshold |
|--------|------------------|
| Uptime | >= 98% |
| Scoring latency | <= 500ms |
| Consensus participation | >= 95% |
| Last-seen freshness | <= 900s old |

Any breached voting threshold results in a `flag` verdict. Peers that pass all
thresholds receive an `endorse` verdict.

## Environment Variables

- `XRPL_FEE_PAYER_SEED`: funded XRPL testnet wallet seed for `--submit`
- `CONFIG_PATH`: optional override for `peer_defense.py` config path

## Example UNL Voting Output

```text
========================================================================
Peer Vote: nHMockFlaggedValidator222222222222222222222222
========================================================================
[INGEST] normalized metrics
{
  "validator_public_key": "nHMockFlaggedValidator222222222222222222222222",
  "uptime_pct": 0.91,
  "scoring_latency_ms": 750,
  "consensus_participation_pct": 0.82,
  "last_seen_utc": "2026-03-23T00:00:00Z",
  "last_seen_age_seconds": 86400,
  "collected_at": "2026-03-23T00:00:05Z"
}
[EVALUATE] verdict=flag breaches=['uptime_below_min', 'latency_above_max', 'consensus_below_min', 'last_seen_stale']
[MEMO] signed payload
{
  "schema": "postfiat.unl_vote.v1",
  "peer_validator_public_key": "nHMockFlaggedValidator222222222222222222222222",
  "verdict": "flag",
  "evaluated_at": "2026-03-24T00:00:00Z",
  "breaches": [
    "uptime_below_min",
    "latency_above_max",
    "consensus_below_min",
    "last_seen_stale"
  ],
  "voter_validator_public_key": "nHUCEXpC5LhFAm1Mmf8TqrzVGt3QCuwWoW2V8PYynDpjZe8m8mHj",
  "metrics_digest_sha256": "abc123...",
  "validator_signature": "ED..."
}
[DRY_RUN] signed_tx_hash=F00DBABE...
```

## License

MIT
