#!/usr/bin/env python3
"""
Peer health signature ingestion and verification engine for PostFiat validators.

Ingests health signature memo transactions from multiple XRPL validator accounts,
cryptographically verifies each signature, merges verified payloads into a local
peer-consensus state, and outputs a multi-node UNL quality summary with
recommended actions (maintain, warn, escalate).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import nacl.signing
from xrpl.clients import JsonRpcClient
from xrpl.core import addresscodec

from unl_voting import (
    DEFAULT_MEMO_FORMAT,
    encode_memo_field,
    format_utc,
    load_voting_config,
    utc_now,
)
from validator_health_signatures import (
    DEFAULT_MEMO_SCHEMA,
    HealthSignatureRecord,
    extract_health_signature_records,
    fetch_health_signature_records,
    health_signature_record_to_dict,
)

DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_WARN_SCORE_THRESHOLD = 0.5
DEFAULT_ESCALATE_SCORE_THRESHOLD = -0.5
DEFAULT_QUORUM_RATIO = 0.5
DEFAULT_FETCH_LIMIT = 10


@dataclass(frozen=True)
class IngestionConfig:
    warn_score_threshold: float = DEFAULT_WARN_SCORE_THRESHOLD
    escalate_score_threshold: float = DEFAULT_ESCALATE_SCORE_THRESHOLD
    quorum_ratio: float = DEFAULT_QUORUM_RATIO


@dataclass(frozen=True)
class PeerConsensusEntry:
    target_address: str
    reporters: tuple[str, ...]
    scores: tuple[float, ...]
    avg_score: float
    min_score: float
    max_score: float
    endorsements: int
    flags: int
    recommended_action: str
    threshold_reason: str


@dataclass(frozen=True)
class IngestionSummary:
    total_records_fetched: int
    valid_records: int
    invalid_records: int
    reporting_validators: tuple[str, ...]
    consensus_entries: tuple[PeerConsensusEntry, ...]
    generated_at: str


@dataclass(frozen=True)
class SimulatedValidator:
    signing_key: nacl.signing.SigningKey
    validator_public_key: str
    wallet_address: str


# ---------------------------------------------------------------------------
# Live XRPL ingestion
# ---------------------------------------------------------------------------


def ingest_from_xrpl(
    rpc_url: str,
    *,
    accounts: list[str],
    limit: int,
    show_invalid: bool,
) -> list[HealthSignatureRecord]:
    client = JsonRpcClient(rpc_url)
    records: list[HealthSignatureRecord] = []
    for account in accounts:
        records.extend(
            fetch_health_signature_records(
                client, account=account, limit=limit, tx_hash=None
            )
        )
    records = sorted(
        records,
        key=lambda r: ((r.ledger_index or 0), r.tx_hash, r.source),
        reverse=True,
    )
    if not show_invalid:
        records = [
            r
            for r in records
            if r.signing_account_matches_claim and r.validator_signature_valid
        ]
    return records


# ---------------------------------------------------------------------------
# State merging
# ---------------------------------------------------------------------------


def build_validator_state(
    records: list[HealthSignatureRecord],
) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    for record in records:
        if not record.validator_signature_valid:
            continue
        payload = record.payload
        node_validator = str(
            payload.get("node_validator")
            or payload.get("node_validator_public_key")
            or ""
        ).strip()
        if not node_validator:
            continue

        ts = str(payload.get("ts") or payload.get("generated_at") or "").strip()
        existing = state.get(node_validator)
        if existing is not None and existing.get("ts", "") >= ts:
            continue

        state[node_validator] = {
            "node_validator": node_validator,
            "node_wallet": str(
                payload.get("node_wallet")
                or payload.get("node_wallet_address")
                or ""
            ).strip(),
            "ts": ts,
            "peer_scores": payload.get("peer_scores") or [],
            "actions": payload.get("actions") or [],
            "local_unl": payload.get("local_unl") or {},
            "tx_hash": record.tx_hash,
        }
    return state


# ---------------------------------------------------------------------------
# Aggregation engine
# ---------------------------------------------------------------------------


def compute_recommended_action(
    avg_score: float, config: IngestionConfig
) -> tuple[str, str]:
    if avg_score >= config.warn_score_threshold:
        action = "maintain"
        reason = (
            f"maintain \u2014 avg score {avg_score:.2f} "
            f">= warn threshold {config.warn_score_threshold:.2f}"
        )
    elif avg_score >= config.escalate_score_threshold:
        action = "warn"
        reason = (
            f"warn \u2014 avg score {avg_score:.2f} "
            f"< warn threshold {config.warn_score_threshold:.2f}"
        )
    else:
        action = "escalate"
        reason = (
            f"escalate \u2014 avg score {avg_score:.2f} "
            f"< escalate threshold {config.escalate_score_threshold:.2f}"
        )
    return action, reason


def aggregate_consensus(
    validator_state: dict[str, dict[str, Any]],
    config: IngestionConfig,
) -> list[PeerConsensusEntry]:
    target_map: dict[str, list[tuple[str, float, str]]] = {}

    for node_validator, entry in validator_state.items():
        for peer in entry.get("peer_scores") or []:
            target = str(peer.get("wallet") or "").strip()
            if not target:
                continue
            score = float(peer.get("score", 0.0))
            status = str(peer.get("status") or "endorse").strip()
            target_map.setdefault(target, []).append((node_validator, score, status))

    entries: list[PeerConsensusEntry] = []
    for target in sorted(target_map):
        reports = target_map[target]
        reporters = tuple(r[0] for r in reports)
        scores = tuple(r[1] for r in reports)
        avg_score = round(sum(scores) / len(scores), 6) if scores else 0.0
        endorsements = sum(1 for r in reports if r[2] == "endorse")
        flags = sum(1 for r in reports if r[2] in ("flag", "jail"))
        action, reason = compute_recommended_action(avg_score, config)

        entries.append(
            PeerConsensusEntry(
                target_address=target,
                reporters=reporters,
                scores=scores,
                avg_score=avg_score,
                min_score=min(scores) if scores else 0.0,
                max_score=max(scores) if scores else 0.0,
                endorsements=endorsements,
                flags=flags,
                recommended_action=action,
                threshold_reason=reason,
            )
        )
    return entries


def build_ingestion_summary(
    all_records: list[HealthSignatureRecord],
    valid_records: list[HealthSignatureRecord],
    consensus_entries: list[PeerConsensusEntry],
) -> IngestionSummary:
    reporting = sorted(
        {
            str(
                r.payload.get("node_validator")
                or r.payload.get("node_validator_public_key")
                or r.account
            ).strip()
            for r in valid_records
            if r.validator_signature_valid
        }
    )
    return IngestionSummary(
        total_records_fetched=len(all_records),
        valid_records=len(valid_records),
        invalid_records=len(all_records) - len(valid_records),
        reporting_validators=tuple(reporting),
        consensus_entries=tuple(consensus_entries),
        generated_at=format_utc(utc_now()),
    )


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

SIMULATED_TARGETS = [
    "nHTargetHealthyAAA111111111111111111111111111",
    "nHTargetMixedBBBB222222222222222222222222222",
    "nHTargetBadCCCCCC333333333333333333333333333",
    "nHTargetSplitDDDD444444444444444444444444444",
]

SIMULATED_SCORE_GRID = [
    # (target_index, validator_index) -> (score, status)
    # Target A: all healthy -> maintain
    {"score": 0.9, "status": "endorse"},
    {"score": 0.85, "status": "endorse"},
    {"score": 0.95, "status": "endorse"},
    # Target B: mixed -> warn
    {"score": 0.3, "status": "flag"},
    {"score": 0.4, "status": "flag"},
    {"score": 0.2, "status": "flag"},
    # Target C: all bad -> escalate
    {"score": -0.8, "status": "jail"},
    {"score": -0.9, "status": "jail"},
    {"score": -0.7, "status": "jail"},
    # Target D: split -> warn
    {"score": 0.9, "status": "endorse"},
    {"score": -0.5, "status": "flag"},
    {"score": 0.2, "status": "endorse"},
]


def generate_simulated_validators(count: int = 3) -> list[SimulatedValidator]:
    validators: list[SimulatedValidator] = []
    for i in range(count):
        signing_key = nacl.signing.SigningKey.generate()
        pub_key = addresscodec.encode_node_public_key(
            b"\xed" + bytes(signing_key.verify_key)
        )
        wallet = f"rSimValidator{i + 1}{'X' * (25 - len(str(i + 1)))}"
        validators.append(
            SimulatedValidator(
                signing_key=signing_key,
                validator_public_key=pub_key,
                wallet_address=wallet,
            )
        )
    return validators


def build_simulated_health_payload(
    validator: SimulatedValidator,
    *,
    peer_scores: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    timestamp: str,
) -> dict[str, Any]:
    canonical_payload = {
        "schema": DEFAULT_MEMO_SCHEMA,
        "node_wallet": validator.wallet_address,
        "node_validator": validator.validator_public_key,
        "ts": timestamp,
        "peer_scores": peer_scores,
        "actions": actions,
        "local_unl": {
            "hash": "sim_unl_hash_placeholder",
            "validators": len(SIMULATED_TARGETS),
            "sites": 1,
            "keys": 1,
            "threshold": "1",
        },
    }
    canonical_json = json.dumps(
        canonical_payload, sort_keys=True, separators=(",", ":")
    )
    signature = (
        validator.signing_key.sign(canonical_json.encode("utf-8"))
        .signature.hex()
        .upper()
    )
    return dict(canonical_payload, validator_signature=signature)


def build_simulated_tx_entry(
    validator: SimulatedValidator,
    signed_payload: dict[str, Any],
    *,
    tx_hash: str,
    ledger_index: int,
) -> dict[str, Any]:
    payload_json = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))
    return {
        "hash": tx_hash,
        "ledger_index": ledger_index,
        "validated": True,
        "tx": {
            "Account": validator.wallet_address,
            "hash": tx_hash,
            "ledger_index": ledger_index,
            "Memos": [
                {
                    "Memo": {
                        "MemoData": encode_memo_field(payload_json),
                        "MemoType": encode_memo_field(DEFAULT_MEMO_SCHEMA),
                        "MemoFormat": encode_memo_field(DEFAULT_MEMO_FORMAT),
                    }
                }
            ],
        },
    }


def run_simulation() -> tuple[list[HealthSignatureRecord], list[dict[str, Any]]]:
    validators = generate_simulated_validators(3)
    timestamp = format_utc(utc_now())
    all_records: list[HealthSignatureRecord] = []
    raw_entries: list[dict[str, Any]] = []

    for v_idx, validator in enumerate(validators):
        peer_scores: list[dict[str, Any]] = []
        for t_idx, target in enumerate(SIMULATED_TARGETS):
            grid_idx = t_idx * len(validators) + v_idx
            score_entry = SIMULATED_SCORE_GRID[grid_idx]
            peer_scores.append(
                {
                    "wallet": target,
                    "score": score_entry["score"],
                    "status": score_entry["status"],
                }
            )

        actions: list[dict[str, Any]] = []
        if v_idx == 0:
            actions.append(
                {
                    "ts": timestamp,
                    "action": "jail",
                    "target": SIMULATED_TARGETS[2],
                }
            )

        signed_payload = build_simulated_health_payload(
            validator,
            peer_scores=peer_scores,
            actions=actions,
            timestamp=timestamp,
        )

        tx_hash = f"SIMTX{v_idx + 1:03d}"
        tx_entry = build_simulated_tx_entry(
            validator,
            signed_payload,
            tx_hash=tx_hash,
            ledger_index=90000000 + v_idx,
        )
        raw_entries.append(tx_entry)
        all_records.extend(extract_health_signature_records(tx_entry))

    return all_records, raw_entries


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_ingestion_results(
    all_records: list[HealthSignatureRecord],
    valid_records: list[HealthSignatureRecord],
    summary: IngestionSummary,
    validator_state: dict[str, dict[str, Any]],
    *,
    mode: str,
    accounts: list[str],
) -> None:
    print("=" * 72)
    print("Peer Health Signature Ingestion and Verification")
    print("=" * 72)
    print(
        f"[INGEST] mode={mode} "
        f"validators={len(accounts)} "
        f"records_fetched={summary.total_records_fetched} "
        f"valid={summary.valid_records} "
        f"invalid={summary.invalid_records}"
    )
    print()

    for record in all_records:
        sig_status = "PASS" if record.validator_signature_valid else "FAIL"
        acct_status = "PASS" if record.signing_account_matches_claim else "FAIL"
        claimed_validator = str(
            record.payload.get("node_validator")
            or record.payload.get("node_validator_public_key")
            or "n/a"
        ).strip()
        print(
            f"[VERIFY] tx={record.tx_hash} "
            f"validator={claimed_validator[:20]}... "
            f"signature={sig_status} "
            f"account_match={acct_status}"
        )
        if record.validation_errors:
            for err in record.validation_errors:
                print(f"[VERIFY]   error: {err}")
    print()

    print(f"[STATE] reporting_validators={len(validator_state)}")
    for node_val, entry in sorted(validator_state.items()):
        print(
            f"[STATE] validator={node_val[:20]}... "
            f"peer_scores={len(entry.get('peer_scores', []))} "
            f"actions={len(entry.get('actions', []))} "
            f"ts={entry.get('ts', 'n/a')}"
        )
    print()

    print("=" * 72)
    print("Multi-Node UNL Quality Summary")
    print("=" * 72)
    for entry in summary.consensus_entries:
        print(
            f"[CONSENSUS] target={entry.target_address[:20]}... "
            f"avg_score={entry.avg_score:.3f} "
            f"reporters={len(entry.reporters)} "
            f"endorsements={entry.endorsements} "
            f"flags={entry.flags} "
            f"action={entry.recommended_action}"
        )
        print(f"[CONSENSUS]   reason: {entry.threshold_reason}")
    print()
    print(f"[SUMMARY] generated_at={summary.generated_at}")
    print()


def consensus_entry_to_dict(entry: PeerConsensusEntry) -> dict[str, Any]:
    return {
        "target_address": entry.target_address,
        "reporters": list(entry.reporters),
        "scores": list(entry.scores),
        "avg_score": entry.avg_score,
        "min_score": entry.min_score,
        "max_score": entry.max_score,
        "endorsements": entry.endorsements,
        "flags": entry.flags,
        "recommended_action": entry.recommended_action,
        "threshold_reason": entry.threshold_reason,
    }


def summary_to_dict(summary: IngestionSummary) -> dict[str, Any]:
    return {
        "total_records_fetched": summary.total_records_fetched,
        "valid_records": summary.valid_records,
        "invalid_records": summary.invalid_records,
        "reporting_validators": list(summary.reporting_validators),
        "consensus_entries": [
            consensus_entry_to_dict(e) for e in summary.consensus_entries
        ],
        "generated_at": summary.generated_at,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Ingest, verify, and aggregate peer health signatures "
            "from XRPL memo transactions into a multi-node UNL quality summary"
        )
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG_PATH, help="Path to config.json"
    )
    parser.add_argument(
        "--rpc-url", help="Override the XRPL JSON-RPC URL for live ingestion"
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--account",
        action="append",
        help="XRPL account to poll for health signature memos (repeatable)",
    )
    source_group.add_argument(
        "--simulate",
        action="store_true",
        help="Run with 3 simulated validators and synthetic health data",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_FETCH_LIMIT,
        help="Maximum records to fetch per account",
    )
    parser.add_argument(
        "--warn-threshold",
        type=float,
        default=DEFAULT_WARN_SCORE_THRESHOLD,
        help=f"Avg score threshold for warn action (default: {DEFAULT_WARN_SCORE_THRESHOLD})",
    )
    parser.add_argument(
        "--escalate-threshold",
        type=float,
        default=DEFAULT_ESCALATE_SCORE_THRESHOLD,
        help=f"Avg score threshold for escalate action (default: {DEFAULT_ESCALATE_SCORE_THRESHOLD})",
    )
    parser.add_argument(
        "--show-invalid",
        action="store_true",
        help="Include records that failed verification",
    )
    parser.add_argument(
        "--json-out", help="Write the aggregated summary as JSON to this path"
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = IngestionConfig(
            warn_score_threshold=args.warn_threshold,
            escalate_score_threshold=args.escalate_threshold,
        )

        if args.simulate:
            all_records, _raw = run_simulation()
            accounts = sorted(
                {
                    str(
                        r.payload.get("node_validator")
                        or r.payload.get("node_validator_public_key")
                        or r.account
                    ).strip()
                    for r in all_records
                }
            )
            mode = "simulate"
        else:
            from pathlib import Path

            config_path = Path(args.config)
            voting_config = load_voting_config(config_path)
            rpc_url = args.rpc_url or voting_config.xrpl_rpc_url
            all_records = ingest_from_xrpl(
                rpc_url,
                accounts=args.account,
                limit=args.limit,
                show_invalid=args.show_invalid,
            )
            accounts = args.account
            mode = "live"

        valid_records = [
            r
            for r in all_records
            if r.signing_account_matches_claim and r.validator_signature_valid
        ]
        invalid_records = [r for r in all_records if r not in valid_records]

        if not all_records:
            print(
                "No health signature memo transactions found", file=sys.stderr
            )
            return 1

        validator_state = build_validator_state(valid_records)
        consensus_entries = aggregate_consensus(validator_state, config)
        summary = build_ingestion_summary(
            all_records, valid_records, consensus_entries
        )

        render_ingestion_results(
            all_records,
            valid_records,
            summary,
            validator_state,
            mode=mode,
            accounts=accounts,
        )

        if args.json_out:
            from pathlib import Path

            Path(args.json_out).write_text(
                json.dumps(summary_to_dict(summary), indent=2)
            )
            print(f"[OUTPUT] json_path={args.json_out}")

        return 0

    except (
        FileNotFoundError,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
