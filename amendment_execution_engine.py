#!/usr/bin/env python3
"""
Amendment execution engine for PostFiat validators.

Monitors the XRPL testnet ledger for UNL amendment proposal memo transactions,
evaluates whether a proposal has reached supermajority consensus (>80% of known
validators endorsed the same amendment), and upon confirmation automatically
updates the local rippled.cfg trusted_validators list and emits a structured
execution receipt memo transaction back to the ledger as proof of compliance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from xrpl.clients import JsonRpcClient
from xrpl.models.requests import AccountTx
from xrpl.models.transactions import Memo

from unl_amendment_proposal import DEFAULT_AMENDMENT_SCHEMA
from unl_governance_enforcer import (
    append_jsonl,
    load_enforcement_config,
    read_trusted_validators,
    run_command,
    update_trusted_validators,
)
from unl_voting import (
    FeePayerContext,
    encode_memo_field,
    format_utc,
    submit_vote_transaction,
    utc_now,
)

DEFAULT_CONFIG_PATH = Path("/home/postfiat/peer-defense/config.json")
DEFAULT_SUPERMAJORITY_THRESHOLD = 0.8
RECEIPT_MEMO_SCHEMA = "postfiat.unl_amendment_receipt.v1"
RECEIPT_MEMO_FORMAT = "application/json"
TESTNET_RPC_URL = "https://s.altnet.rippletest.net:51234"


@dataclass(frozen=True)
class ExecutionConfig:
    supermajority_threshold: float
    known_proposer_count: int
    poll_accounts: tuple[str, ...]
    proposal_window_seconds: int
    xrpl_rpc_url: str
    rippled_cfg_path: Path
    trusted_validators_section: str
    reload_command: tuple[str, ...]
    alert_log_path: Path


@dataclass(frozen=True)
class DecodedAmendmentProposal:
    tx_hash: str
    account: str
    ledger_index: Optional[int]
    amendment_action: str
    target_validator_public_key: str
    quorum_met: bool
    agreement_ratio: float
    contributing_peers: tuple[dict[str, Any], ...]
    score_summary: dict[str, Any]
    proposed_at: str
    proposing_validator_public_key: str
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class ProposalGroup:
    target_validator_public_key: str
    amendment_action: str
    proposals: tuple[DecodedAmendmentProposal, ...]
    unique_endorsing_accounts: tuple[str, ...]


@dataclass(frozen=True)
class SupermajorityResult:
    group: ProposalGroup
    endorsement_count: int
    known_validator_count: int
    endorsement_ratio: float
    passed: bool


@dataclass(frozen=True)
class ExecutionReceipt:
    proposal_id: str
    amendment_action: str
    target_validator_public_key: str
    result: str
    resulting_validator_set_hash: str
    executed_at: str
    endorsement_count: int
    endorsement_ratio: float


# ---------------------------------------------------------------------------
# Layer 1: Ledger Listener
# ---------------------------------------------------------------------------


def decode_amendment_memo_payload(memo: dict[str, Any]) -> Optional[dict[str, Any]]:
    memo_type_hex = memo.get("MemoType", memo.get("memo_type"))
    if not memo_type_hex:
        return None

    try:
        memo_type = bytes.fromhex(memo_type_hex).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None

    if memo_type != DEFAULT_AMENDMENT_SCHEMA:
        return None

    data_hex = memo.get("MemoData", memo.get("memo_data"))
    if not data_hex:
        return None

    memo_format_hex = memo.get("MemoFormat", memo.get("memo_format"))
    is_zlib = False
    if memo_format_hex:
        try:
            memo_format = bytes.fromhex(memo_format_hex).decode("utf-8")
            is_zlib = "zlib" in memo_format.lower()
        except (ValueError, UnicodeDecodeError):
            pass

    raw_bytes = bytes.fromhex(data_hex)
    if is_zlib:
        try:
            decompressed = zlib.decompress(raw_bytes)
        except zlib.error:
            return None
        text = decompressed.decode("utf-8")
    else:
        text = raw_bytes.decode("utf-8")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    return payload


def extract_amendment_proposals_from_tx(
    raw_entry: dict[str, Any],
) -> list[DecodedAmendmentProposal]:
    if isinstance(raw_entry.get("tx"), dict):
        tx_container = raw_entry["tx"]
    elif isinstance(raw_entry.get("tx_json"), dict):
        tx_container = raw_entry["tx_json"]
    else:
        tx_container = raw_entry
    if not isinstance(tx_container, dict):
        return []

    account = str(tx_container.get("Account", "")).strip()
    tx_hash = str(
        tx_container.get("hash") or raw_entry.get("hash") or ""
    ).strip() or "unknown"
    ledger_index_raw = raw_entry.get("ledger_index", tx_container.get("ledger_index"))
    try:
        ledger_index = int(ledger_index_raw) if ledger_index_raw is not None else None
    except (TypeError, ValueError):
        ledger_index = None

    memos = tx_container.get("Memos") or tx_container.get("memos") or []
    proposals: list[DecodedAmendmentProposal] = []

    for memo_wrapper in memos:
        memo = memo_wrapper
        while isinstance(memo, dict) and isinstance(memo.get("Memo"), dict):
            memo = memo["Memo"]
        if not isinstance(memo, dict):
            continue

        payload = decode_amendment_memo_payload(memo)
        if payload is None:
            continue

        amendment_action = str(payload.get("amendment_action", "")).strip()
        target = str(payload.get("target_validator_public_key", "")).strip()
        if not amendment_action or not target:
            continue

        proposals.append(
            DecodedAmendmentProposal(
                tx_hash=tx_hash,
                account=account,
                ledger_index=ledger_index,
                amendment_action=amendment_action,
                target_validator_public_key=target,
                quorum_met=bool(payload.get("quorum_met", False)),
                agreement_ratio=float(payload.get("agreement_ratio", 0.0)),
                contributing_peers=tuple(payload.get("contributing_peers", [])),
                score_summary=payload.get("score_summary", {}),
                proposed_at=str(payload.get("proposed_at", "")),
                proposing_validator_public_key=str(
                    payload.get("proposing_validator_public_key", "")
                ),
                raw_payload=payload,
            )
        )

    return proposals


def fetch_amendment_proposals(
    client: JsonRpcClient,
    *,
    accounts: tuple[str, ...],
    limit: int = 50,
) -> list[DecodedAmendmentProposal]:
    seen_tx_hashes: set[str] = set()
    all_proposals: list[DecodedAmendmentProposal] = []

    for account in accounts:
        marker: Any = None
        page_limit = min(max(limit * 4, 20), 200)
        fetched = 0

        while fetched < limit:
            request_kwargs: dict[str, Any] = {
                "account": account,
                "ledger_index_min": -1,
                "ledger_index_max": -1,
                "limit": page_limit,
                "forward": False,
            }
            if marker is not None:
                request_kwargs["marker"] = marker
            response = client.request(AccountTx(**request_kwargs))
            transactions = response.result.get("transactions", [])
            if not transactions:
                break

            for raw_entry in transactions:
                if not isinstance(raw_entry, dict):
                    continue
                proposals = extract_amendment_proposals_from_tx(raw_entry)
                for proposal in proposals:
                    if proposal.tx_hash not in seen_tx_hashes:
                        seen_tx_hashes.add(proposal.tx_hash)
                        all_proposals.append(proposal)
                fetched += 1

            marker = response.result.get("marker")
            if marker is None:
                break

    return sorted(
        all_proposals,
        key=lambda p: (p.ledger_index or 0, p.tx_hash),
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Layer 2: Supermajority Evaluation
# ---------------------------------------------------------------------------


def group_proposals(
    proposals: list[DecodedAmendmentProposal],
) -> list[ProposalGroup]:
    groups: dict[tuple[str, str], list[DecodedAmendmentProposal]] = {}
    for proposal in proposals:
        key = (proposal.target_validator_public_key, proposal.amendment_action)
        groups.setdefault(key, []).append(proposal)

    result: list[ProposalGroup] = []
    for (target, action), group_proposals_list in groups.items():
        unique_accounts = sorted(
            set(p.account for p in group_proposals_list if p.account)
        )
        result.append(
            ProposalGroup(
                target_validator_public_key=target,
                amendment_action=action,
                proposals=tuple(group_proposals_list),
                unique_endorsing_accounts=tuple(unique_accounts),
            )
        )

    return result


def evaluate_supermajority(
    group: ProposalGroup,
    known_validator_count: int,
    threshold: float,
) -> SupermajorityResult:
    endorsement_count = len(group.unique_endorsing_accounts)
    ratio = endorsement_count / known_validator_count if known_validator_count > 0 else 0.0
    passed = ratio > threshold

    return SupermajorityResult(
        group=group,
        endorsement_count=endorsement_count,
        known_validator_count=known_validator_count,
        endorsement_ratio=round(ratio, 6),
        passed=passed,
    )


# ---------------------------------------------------------------------------
# Layer 3: Config Update
# ---------------------------------------------------------------------------


def compute_validator_set_hash(validator_keys: tuple[str, ...]) -> str:
    canonical = "\n".join(sorted(validator_keys))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def execute_amendment(
    result: SupermajorityResult,
    config: ExecutionConfig,
) -> tuple[bool, str, str]:
    config_text = config.rippled_cfg_path.read_text()
    current_state = read_trusted_validators(config_text, config.trusted_validators_section)

    if not result.passed:
        validator_set_hash = compute_validator_set_hash(current_state.validator_keys)
        return False, "", validator_set_hash

    action = result.group.amendment_action
    target = result.group.target_validator_public_key

    if action == "flag":
        alert_entry = {
            "timestamp": format_utc(utc_now()),
            "event": "UNL_AMENDMENT_FLAG",
            "target_validator_public_key": target,
            "amendment_action": action,
            "endorsement_count": result.endorsement_count,
            "endorsement_ratio": result.endorsement_ratio,
        }
        append_jsonl(config.alert_log_path, alert_entry)
        validator_set_hash = compute_validator_set_hash(current_state.validator_keys)
        return False, "", validator_set_hash

    if action == "remove":
        update = update_trusted_validators(
            config_text,
            section_name=config.trusted_validators_section,
            remove_keys=(target,),
        )
    elif action == "add":
        update = update_trusted_validators(
            config_text,
            section_name=config.trusted_validators_section,
            add_keys=(target,),
        )
    else:
        validator_set_hash = compute_validator_set_hash(current_state.validator_keys)
        return False, "", validator_set_hash

    if update.changed:
        config.rippled_cfg_path.write_text(update.updated_text)
        run_command(config.reload_command)

    validator_set_hash = compute_validator_set_hash(update.after_keys)
    return update.changed, update.diff, validator_set_hash


# ---------------------------------------------------------------------------
# Layer 4: Execution Receipt
# ---------------------------------------------------------------------------


def build_proposal_id(
    target: str,
    action: str,
    endorsing_accounts: tuple[str, ...],
) -> str:
    canonical = json.dumps(
        {
            "target_validator_public_key": target,
            "amendment_action": action,
            "endorsing_accounts": sorted(endorsing_accounts),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_execution_receipt(
    result: SupermajorityResult,
    changed: bool,
    validator_set_hash: str,
) -> ExecutionReceipt:
    group = result.group
    proposal_id = build_proposal_id(
        group.target_validator_public_key,
        group.amendment_action,
        group.unique_endorsing_accounts,
    )
    return ExecutionReceipt(
        proposal_id=proposal_id,
        amendment_action=group.amendment_action,
        target_validator_public_key=group.target_validator_public_key,
        result="PASS" if result.passed else "FAIL",
        resulting_validator_set_hash=validator_set_hash,
        executed_at=format_utc(utc_now()),
        endorsement_count=result.endorsement_count,
        endorsement_ratio=result.endorsement_ratio,
    )


def build_receipt_memo(receipt: ExecutionReceipt) -> Memo:
    payload = {
        "schema": RECEIPT_MEMO_SCHEMA,
        "proposal_id": receipt.proposal_id,
        "amendment_action": receipt.amendment_action,
        "target_validator_public_key": receipt.target_validator_public_key,
        "result": receipt.result,
        "resulting_validator_set_hash": receipt.resulting_validator_set_hash,
        "executed_at": receipt.executed_at,
        "endorsement_count": receipt.endorsement_count,
        "endorsement_ratio": receipt.endorsement_ratio,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return Memo(
        memo_data=encode_memo_field(payload_json),
        memo_format=encode_memo_field(RECEIPT_MEMO_FORMAT),
        memo_type=encode_memo_field(RECEIPT_MEMO_SCHEMA),
    )


def submit_execution_receipt(
    client: JsonRpcClient,
    wallet_context: FeePayerContext,
    receipt: ExecutionReceipt,
) -> dict[str, Any]:
    memo = build_receipt_memo(receipt)
    return submit_vote_transaction(client, wallet_context, memo)


# ---------------------------------------------------------------------------
# Render Functions
# ---------------------------------------------------------------------------


def render_listener_results(proposals: list[DecodedAmendmentProposal]) -> None:
    print("=" * 72)
    print("Amendment Execution Engine - Ledger Listener")
    print("=" * 72)
    print(f"[LISTEN] detected_proposals={len(proposals)}")
    for p in proposals:
        print(
            f"[LISTEN] tx_hash={p.tx_hash} "
            f"account={p.account} "
            f"target={p.target_validator_public_key} "
            f"action={p.amendment_action} "
            f"ledger_index={p.ledger_index}"
        )
    print()


def render_groups(groups: list[ProposalGroup]) -> None:
    print("=" * 72)
    print("Proposal Grouping")
    print("=" * 72)
    for group in groups:
        print(
            f"[GROUP] target={group.target_validator_public_key} "
            f"action={group.amendment_action} "
            f"proposals={len(group.proposals)} "
            f"unique_endorsers={len(group.unique_endorsing_accounts)}"
        )
        for account in group.unique_endorsing_accounts:
            print(f"[GROUP]   endorser={account}")
    print()


def render_supermajority_evaluation(results: list[SupermajorityResult]) -> None:
    print("=" * 72)
    print("Supermajority Evaluation")
    print("=" * 72)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"[SUPERMAJORITY] target={result.group.target_validator_public_key} "
            f"action={result.group.amendment_action} "
            f"endorsements={result.endorsement_count}/{result.known_validator_count} "
            f"ratio={result.endorsement_ratio:.4f} "
            f"threshold>{DEFAULT_SUPERMAJORITY_THRESHOLD:.4f} "
            f"result={status}"
        )
    print()


def render_execution_result(
    result: SupermajorityResult,
    changed: bool,
    diff: str,
    validator_set_hash: str,
) -> None:
    action = result.group.amendment_action
    target = result.group.target_validator_public_key
    if changed:
        print(
            f"[EXECUTE] target={target} "
            f"action={action} "
            f"config_updated=True "
            f"validator_set_hash={validator_set_hash}"
        )
        if diff:
            print("[CONFIG_DIFF]")
            print(diff)
    elif result.passed and action == "flag":
        print(
            f"[EXECUTE] target={target} "
            f"action={action} "
            f"config_updated=False "
            f"reason=flag_action_logged_only"
        )
    elif not result.passed:
        print(
            f"[EXECUTE] target={target} "
            f"action={action} "
            f"config_updated=False "
            f"reason=supermajority_not_reached"
        )


def render_receipt_submission(
    receipt: ExecutionReceipt,
    submit_result: Optional[dict[str, Any]],
) -> None:
    print(
        f"[RECEIPT] proposal_id={receipt.proposal_id} "
        f"target={receipt.target_validator_public_key} "
        f"action={receipt.amendment_action} "
        f"result={receipt.result}"
    )
    if submit_result:
        print(
            f"[RECEIPT] transaction_hash={submit_result.get('transaction_hash', 'n/a')} "
            f"engine_result={submit_result.get('result', {}).get('meta', {}).get('TransactionResult', submit_result.get('engine_result', 'n/a'))}"
        )


# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------


def load_execution_config(config_path: Path) -> ExecutionConfig:
    data = json.loads(config_path.read_text())
    amendment_exec = data.get("amendment_execution")
    if not amendment_exec:
        raise ValueError("config.json is missing the amendment_execution section")

    enforcement = data.get("unl_enforcement")
    if not enforcement:
        raise ValueError("config.json is missing the unl_enforcement section")

    enforcement_config = load_enforcement_config(config_path)

    poll_accounts_raw = amendment_exec.get("poll_accounts", [])
    if not isinstance(poll_accounts_raw, list) or not poll_accounts_raw:
        raise ValueError("amendment_execution.poll_accounts must be a non-empty array")

    known_count = int(amendment_exec.get("known_proposer_count", len(poll_accounts_raw)))

    return ExecutionConfig(
        supermajority_threshold=float(
            amendment_exec.get("supermajority_threshold", DEFAULT_SUPERMAJORITY_THRESHOLD)
        ),
        known_proposer_count=known_count,
        poll_accounts=tuple(str(a).strip() for a in poll_accounts_raw),
        proposal_window_seconds=int(amendment_exec.get("proposal_window_seconds", 600)),
        xrpl_rpc_url=str(amendment_exec.get("xrpl_rpc_url", TESTNET_RPC_URL)),
        rippled_cfg_path=enforcement_config.rippled_cfg_path,
        trusted_validators_section=enforcement_config.trusted_validators_section,
        reload_command=enforcement_config.peer_filter_reload_command,
        alert_log_path=enforcement_config.alert_log_path,
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def run_execution_pipeline(
    config: ExecutionConfig,
    *,
    client: JsonRpcClient,
    wallet_context: FeePayerContext,
    dry_run: bool = True,
) -> int:
    # Layer 1: Fetch proposals from ledger
    proposals = fetch_amendment_proposals(
        client, accounts=config.poll_accounts, limit=50
    )
    render_listener_results(proposals)

    if not proposals:
        print("[RESULT] No amendment proposals found on ledger")
        return 0

    # Layer 2: Group and evaluate supermajority
    groups = group_proposals(proposals)
    render_groups(groups)

    supermajority_results = [
        evaluate_supermajority(
            group, config.known_proposer_count, config.supermajority_threshold
        )
        for group in groups
    ]
    render_supermajority_evaluation(supermajority_results)

    # Layer 3 & 4: Execute amendments and submit receipts
    print("=" * 72)
    print("Execution & Receipts")
    print("=" * 72)

    pass_count = 0
    fail_count = 0

    for sm_result in supermajority_results:
        changed, diff, validator_set_hash = execute_amendment(sm_result, config)
        render_execution_result(sm_result, changed, diff, validator_set_hash)

        if sm_result.passed:
            pass_count += 1
        else:
            fail_count += 1

        receipt = build_execution_receipt(sm_result, changed, validator_set_hash)

        if sm_result.passed and not dry_run:
            try:
                submit_result = submit_execution_receipt(
                    client, wallet_context, receipt
                )
                render_receipt_submission(receipt, submit_result)
            except Exception as exc:
                print(f"[RECEIPT] ERROR: {exc}")
                render_receipt_submission(receipt, None)
        else:
            if dry_run and sm_result.passed:
                print(f"[RECEIPT] dry_run=True proposal_id={receipt.proposal_id}")
            render_receipt_submission(receipt, None)

    print()
    print("=" * 72)
    print(
        f"[RESULT] groups_evaluated={len(supermajority_results)} "
        f"passed={pass_count} "
        f"failed={fail_count}"
    )

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor XRPL ledger for amendment proposals, evaluate supermajority, "
        "update rippled.cfg, and emit execution receipts"
    )
    parser.add_argument(
        "--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json"
    )
    parser.add_argument(
        "--submit", action="store_true", help="Submit receipt transactions to XRPL"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Dry-run mode (default)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        help="Override supermajority threshold (0.0-1.0)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run in continuous polling mode",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=60,
        help="Seconds between polls in continuous mode (default 60)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = load_execution_config(Path(args.config))

        if args.threshold is not None:
            config = ExecutionConfig(
                supermajority_threshold=args.threshold,
                known_proposer_count=config.known_proposer_count,
                poll_accounts=config.poll_accounts,
                proposal_window_seconds=config.proposal_window_seconds,
                xrpl_rpc_url=config.xrpl_rpc_url,
                rippled_cfg_path=config.rippled_cfg_path,
                trusted_validators_section=config.trusted_validators_section,
                reload_command=config.reload_command,
                alert_log_path=config.alert_log_path,
            )

        dry_run = not args.submit
        client = JsonRpcClient(config.xrpl_rpc_url)

        from unl_voting import resolve_fee_payer_wallet, load_voting_config

        voting_config = load_voting_config(Path(args.config))
        wallet_context = resolve_fee_payer_wallet(voting_config, allow_ephemeral=dry_run)

        if args.continuous:
            while True:
                run_execution_pipeline(
                    config, client=client, wallet_context=wallet_context, dry_run=dry_run
                )
                print(f"\n[POLL] sleeping {args.poll_interval}s before next cycle...\n")
                time.sleep(args.poll_interval)
        else:
            return run_execution_pipeline(
                config, client=client, wallet_context=wallet_context, dry_run=dry_run
            )

    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user")
        return 0


if __name__ == "__main__":
    sys.exit(main())
