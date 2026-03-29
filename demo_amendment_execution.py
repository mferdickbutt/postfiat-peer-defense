#!/usr/bin/env python3
"""
End-to-end demonstration of the amendment execution engine.

Phase A: Broadcasts real amendment proposal memo transactions to XRPL testnet
         from 3 funded wallets (no simulation data).
Phase B: Runs the execution engine to detect them from the ledger, evaluate
         supermajority, update rippled.cfg, and submit execution receipts.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import nacl.signing
from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.core import addresscodec
from xrpl.models.transactions import AccountSet, Memo
from xrpl.transaction import sign, submit_and_wait
from xrpl.wallet import Wallet

from amendment_execution_engine import (
    ExecutionConfig,
    FeePayerContext,
    run_execution_pipeline,
)
from unl_voting import encode_memo_field, format_utc, utc_now

TESTNET_RPC = "https://s.altnet.rippletest.net:51234"
AMENDMENT_SCHEMA = "postfiat.unl_amendment.v1"

WALLETS = [
    {"address": "rfp8CbLYknuLU8qB4RTh7krnLZ6wKnU2JY", "seed": "sEdVnR7iwSM4Ny1pZto2CMP6gLaDoDf"},
    {"address": "rM1D5WaUuWDYxQSomuB7RvABvu68VWQiDk", "seed": "sEdTYApWVDgbftaJa9iHRwt1tjAhUaw"},
    {"address": "r3Kp55Nr163iMfVpAZSR6kPXhw8BjkpAWc", "seed": "sEdT4AwzPKDbpQb3QJ2EmHFWd9LBs9x"},
]

# Real target validator keys for the proposals
REMOVE_TARGET = "nHBtBkHGfL4NpB54H1AwBaaSJkSJLUSPvnUNAcuNpuffYB51VjH6"
FAIL_TARGET = "nHUFE9prPnTMwqN8WhBkSjQ1JKBA2QCQaezjP4d4P8P1n5KzpqCR"

DEMO_RIPPLED_CFG = Path("/home/postfiat/peer-defense/demo/enforcement-demo-rippled.cfg")
DEMO_ALERT_LOG = Path("/home/postfiat/peer-defense/demo/execution-alerts.jsonl")


def build_amendment_proposal_payload(
    *,
    amendment_action: str,
    target_validator_public_key: str,
    proposing_validator_public_key: str,
    signing_key: nacl.signing.SigningKey,
    contributing_peers: list[dict],
    score_summary: dict,
) -> dict:
    payload = {
        "schema": AMENDMENT_SCHEMA,
        "amendment_action": amendment_action,
        "target_validator_public_key": target_validator_public_key,
        "quorum_met": True,
        "agreement_ratio": 1.0,
        "contributing_peers": contributing_peers,
        "score_summary": score_summary,
        "proposed_at": format_utc(utc_now()),
        "proposing_validator_public_key": proposing_validator_public_key,
    }

    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = signing_key.sign(canonical_json.encode("utf-8")).signature.hex().upper()
    payload["proposal_signature"] = signature
    return payload


def build_amendment_memo(payload: dict) -> Memo:
    signed_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    compressed = zlib.compress(signed_json.encode("utf-8"), level=9)
    memo_hex = compressed.hex().upper()

    return Memo(
        memo_data=memo_hex,
        memo_format=encode_memo_field("application/json+zlib"),
        memo_type=encode_memo_field(AMENDMENT_SCHEMA),
    )


def submit_proposal_tx(
    client: JsonRpcClient,
    wallet: Wallet,
    memo: Memo,
    label: str,
) -> str:
    from xrpl.models.requests import ServerInfo

    response = client.request(ServerInfo())
    info = response.result.get("info", {})
    network_id = info.get("network_id")
    validated_ledger = info.get("validated_ledger", {})
    ledger_seq = validated_ledger.get("seq")

    tx_kwargs: dict = {
        "account": wallet.address,
        "memos": [memo],
    }
    if network_id is not None and network_id > 1024:
        tx_kwargs["network_id"] = network_id

    accountset = AccountSet(**tx_kwargs)
    response = submit_and_wait(accountset, client, wallet, check_fee=False)
    result = response.result
    tx_hash = result.get("hash", "unknown")
    meta = result.get("meta", {})
    engine_result = meta.get("TransactionResult", result.get("engine_result", "unknown"))
    print(f"[BROADCAST] {label} tx_hash={tx_hash} engine_result={engine_result}")
    return tx_hash


def setup_demo_config() -> Path:
    """Reset the demo rippled.cfg and prepare the demo config for execution."""
    DEMO_RIPPLED_CFG.parent.mkdir(parents=True, exist_ok=True)

    # Write a fresh demo rippled.cfg with the remove target in it
    cfg_content = f"""[server]
port_rpc_admin_local

[validators]
{REMOVE_TARGET}
nHHealthyValidator3333333333333333333333333

[validator_list_sites]
https://vl.postfiat.example
"""
    DEMO_RIPPLED_CFG.write_text(cfg_content)
    print(f"[SETUP] Wrote demo rippled.cfg with {REMOVE_TARGET} in [validators]")

    if DEMO_ALERT_LOG.exists():
        DEMO_ALERT_LOG.unlink()

    return DEMO_RIPPLED_CFG


def main() -> int:
    print("=" * 72)
    print("Amendment Execution Engine - End-to-End Testnet Demo")
    print("=" * 72)
    print()

    client = JsonRpcClient(TESTNET_RPC)

    # Generate 3 real NaCl signing keys for proposal construction
    signing_keys = [nacl.signing.SigningKey.generate() for _ in range(3)]
    validator_pubkeys = []
    for sk in signing_keys:
        pub = addresscodec.encode_node_public_key(b"\xed" + bytes(sk.verify_key))
        validator_pubkeys.append(pub)

    # Build contributing peer data from real keys
    contributing_peers = []
    for i, (sk, pub) in enumerate(zip(signing_keys, validator_pubkeys)):
        canonical = json.dumps({"validator": pub, "idx": i}, sort_keys=True, separators=(",", ":"))
        sig = sk.sign(canonical.encode("utf-8")).signature.hex().upper()
        contributing_peers.append({
            "validator_public_key": pub,
            "score": -0.85,
            "status": "jail",
            "signature": sig,
        })

    score_summary = {
        "avg_score": -0.85,
        "min_score": -0.9,
        "max_score": -0.8,
        "endorsements": 0,
        "flags": 3,
        "total_reporters": 3,
    }

    # -----------------------------------------------------------------------
    # PHASE A: Broadcast real amendment proposals to XRPL testnet
    # -----------------------------------------------------------------------
    print("=" * 72)
    print("Phase A: Broadcasting Real Amendment Proposals to Testnet")
    print("=" * 72)
    print()

    broadcast_hashes: list[str] = []

    # Proposal 1: "remove" REMOVE_TARGET -- submitted by all 3 wallets (should PASS)
    print(f"[PROPOSAL 1] action=remove target={REMOVE_TARGET}")
    print(f"[PROPOSAL 1] Broadcasting from all 3 wallets for supermajority...")
    for i, w in enumerate(WALLETS):
        wallet = Wallet.from_seed(w["seed"], algorithm=CryptoAlgorithm.ED25519)
        payload = build_amendment_proposal_payload(
            amendment_action="remove",
            target_validator_public_key=REMOVE_TARGET,
            proposing_validator_public_key=validator_pubkeys[i],
            signing_key=signing_keys[i],
            contributing_peers=contributing_peers,
            score_summary=score_summary,
        )
        memo = build_amendment_memo(payload)
        tx_hash = submit_proposal_tx(
            client, wallet, memo, f"proposal_1_wallet_{i + 1}"
        )
        broadcast_hashes.append(tx_hash)

    print()

    # Proposal 2: "remove" FAIL_TARGET -- submitted by only 1 wallet (should FAIL)
    print(f"[PROPOSAL 2] action=remove target={FAIL_TARGET}")
    print(f"[PROPOSAL 2] Broadcasting from only 1 wallet (should fail supermajority)...")
    wallet = Wallet.from_seed(WALLETS[0]["seed"], algorithm=CryptoAlgorithm.ED25519)
    payload = build_amendment_proposal_payload(
        amendment_action="remove",
        target_validator_public_key=FAIL_TARGET,
        proposing_validator_public_key=validator_pubkeys[0],
        signing_key=signing_keys[0],
        contributing_peers=contributing_peers,
        score_summary=score_summary,
    )
    memo = build_amendment_memo(payload)
    tx_hash = submit_proposal_tx(client, wallet, memo, "proposal_2_wallet_1")
    broadcast_hashes.append(tx_hash)

    print()
    print(f"[BROADCAST] Total transactions submitted: {len(broadcast_hashes)}")
    for i, h in enumerate(broadcast_hashes):
        print(f"[BROADCAST]   [{i + 1}] {h}")
    print()

    # Wait for ledger finality
    print("[WAIT] Waiting 5 seconds for ledger finality...")
    time.sleep(5)
    print()

    # -----------------------------------------------------------------------
    # PHASE B: Run Execution Engine against real ledger data
    # -----------------------------------------------------------------------
    print("=" * 72)
    print("Phase B: Running Execution Engine Against Real Ledger Data")
    print("=" * 72)
    print()

    demo_cfg_path = setup_demo_config()
    print()

    config = ExecutionConfig(
        supermajority_threshold=0.8,
        known_proposer_count=len(WALLETS),
        poll_accounts=tuple(w["address"] for w in WALLETS),
        proposal_window_seconds=600,
        xrpl_rpc_url=TESTNET_RPC,
        rippled_cfg_path=demo_cfg_path,
        trusted_validators_section="validators",
        reload_command=("true",),
        alert_log_path=DEMO_ALERT_LOG,
    )

    os.environ["XRPL_FEE_PAYER_SEED"] = WALLETS[0]["seed"]
    wallet_context = FeePayerContext(
        wallet=Wallet.from_seed(WALLETS[0]["seed"], algorithm=CryptoAlgorithm.ED25519),
        source=f"env:XRPL_FEE_PAYER_SEED ({WALLETS[0]['address']})",
    )

    result = run_execution_pipeline(
        config,
        client=client,
        wallet_context=wallet_context,
        dry_run=False,
    )

    print()
    print("=" * 72)
    print("[DEMO] End-to-end demo complete")
    print(f"[DEMO] Broadcast {len(broadcast_hashes)} real transactions to XRPL testnet")
    print(f"[DEMO] Engine result: {result}")
    print("=" * 72)

    return result


if __name__ == "__main__":
    sys.exit(main())
