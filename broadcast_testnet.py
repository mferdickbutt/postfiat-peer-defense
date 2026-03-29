#!/usr/bin/env python3
"""
Broadcasts 3 health signature memo transactions to XRPL testnet,
one per simulated validator, each with a distinct funded wallet.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from validator_health_signatures import main as hs_main

TESTNET_RPC = "https://s.altnet.rippletest.net:51234"

VALIDATORS = [
    {
        "keys_file": "/tmp/vkeys1.json",
        "wallet_address": "rfp8CbLYknuLU8qB4RTh7krnLZ6wKnU2JY",
        "seed": "sEdVnR7iwSM4Ny1pZto2CMP6gLaDoDf",
    },
    {
        "keys_file": "/tmp/vkeys2.json",
        "wallet_address": "rM1D5WaUuWDYxQSomuB7RvABvu68VWQiDk",
        "seed": "sEdTYApWVDgbftaJa9iHRwt1tjAhUaw",
    },
    {
        "keys_file": "/tmp/vkeys3.json",
        "wallet_address": "r3Kp55Nr163iMfVpAZSR6kPXhw8BjkpAWc",
        "seed": "sEdT4AwzPKDbpQb3QJ2EmHFWd9LBs9x",
    },
]

BASE_CONFIG = {
    "unl_voting": {
        "uptime_min_pct": 0.98,
        "latency_max_ms": 500,
        "consensus_min_pct": 0.95,
        "last_seen_max_age_seconds": 900,
        "xrpl_rpc_url": TESTNET_RPC,
        "validator_keys_path": "",  # filled per validator
        "fee_payer_seed_env": "XRPL_FEE_PAYER_SEED",
        "dry_run_default": False,
    },
    "unl_enforcement": {
        "rippled_cfg_path": "/home/postfiat/peer-defense/demo/enforcement-demo-rippled.cfg",
        "trusted_validators_section": "validators",
        "peer_filter_reload_command": ["true"],
        "warn_cooldown_minutes": 60,
        "alert_log_path": "/home/postfiat/peer-defense/demo/enforcement-alerts.jsonl",
        "recheck_schedule_path": "/tmp/rechecks.jsonl",
    },
}

tx_hashes = []

for i, v in enumerate(VALIDATORS, start=1):
    print(f"\n{'='*60}")
    print(f"Broadcasting validator {i}: {v['wallet_address']}")
    print(f"{'='*60}")

    config = json.loads(json.dumps(BASE_CONFIG))
    config["unl_voting"]["validator_keys_path"] = v["keys_file"]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as cfg_file:
        json.dump(config, cfg_file)
        cfg_path = cfg_file.name

    os.environ["XRPL_FEE_PAYER_SEED"] = v["seed"]

    rc = hs_main([
        "--config", cfg_path,
        "--rpc-url", TESTNET_RPC,
        "broadcast",
        "--simulate",
        "--submit",
        "--node-wallet-address", v["wallet_address"],
    ])

    Path(cfg_path).unlink(missing_ok=True)

    if rc != 0:
        print(f"ERROR: broadcast failed for validator {i}", file=sys.stderr)
        sys.exit(1)

print("\n\nAll 3 health signatures broadcast successfully.")
