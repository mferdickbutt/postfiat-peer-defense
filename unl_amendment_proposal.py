#!/usr/bin/env python3
"""
Consensus-driven UNL amendment proposal module for PostFiat validators.

Consumes the aggregated multi-node peer-consensus state from
health_signature_ingestion.py, applies supermajority quorum thresholds
(>2/3 agreement) to determine amendment actions (add/remove/flag),
and constructs signed XRPL testnet memo transactions encoding the
proposed amendment with full provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import nacl.signing
from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.core import addresscodec
from xrpl.models.transactions import AccountSet, Memo
from xrpl.transaction import sign, submit_and_wait
from xrpl.wallet import Wallet

from unl_voting import (
    DEFAULT_MEMO_FORMAT,
    FeePayerContext,
    ValidatorIdentity,
    build_dry_run_transaction,
    encode_memo_field,
    format_utc,
    load_validator_identity,
    load_voting_config,
    resolve_fee_payer_wallet,
    sign_with_validator_key,
    submit_vote_transaction,
    utc_now,
)

DEFAULT_AMENDMENT_SCHEMA = "postfiat.unl_amendment.v1"
DEFAULT_QUORUM_RATIO = 2 / 3
DEFAULT_CONFIG_PATH = Path("/home/postfiat/peer-defense/config.json")
TESTNET_RPC_URL = "https://s.altnet.rippletest.net:51234"


@dataclass(frozen=True)
class AmendmentConfig:
    quorum_ratio: float = DEFAULT_QUORUM_RATIO
    dry_run: bool = True


@dataclass(frozen=True)
class PeerContribution:
    validator_public_key: str
    score: float
    status: str
    signature: str


@dataclass(frozen=True)
class ScoreSummary:
    avg_score: float
    min_score: float
    max_score: float
    endorsements: int
    flags: int
    total_reporters: int


@dataclass(frozen=True)
class QuorumResult:
    quorum_met: bool
    agreement_count: int
    total_reporters: int
    agreement_ratio: float


@dataclass(frozen=True)
class AmendmentProposal:
    amendment_action: str
    target_validator_public_key: str
    quorum_met: bool
    agreement_ratio: float
    contributing_peers: tuple[PeerContribution, ...]
    score_summary: ScoreSummary
    proposed_at: str
    proposing_validator_public_key: str


@dataclass(frozen=True)
class SignedAmendmentProposal:
    proposal: AmendmentProposal
    signed_payload: dict[str, Any]
    memo: Memo
    memo_hex: str
    proposal_signature: str


def map_consensus_action_to_amendment(action: str) -> str:
    mapping = {
        "escalate": "remove",
        "warn": "flag",
        "maintain": "add",
    }
    if action not in mapping:
        raise ValueError(f"unknown consensus action '{action}', expected one of {list(mapping)}")
    return mapping[action]


def evaluate_quorum(
    amendment_action: str,
    contributions: tuple[PeerContribution, ...],
    config: AmendmentConfig,
) -> QuorumResult:
    if amendment_action == "remove":
        agreeing_statuses = {"jail", "flag"}
    elif amendment_action == "flag":
        agreeing_statuses = {"flag", "jail"}
    else:
        agreeing_statuses = {"endorse"}

    agreement_count = sum(
        1 for c in contributions if c.status in agreeing_statuses
    )
    total = len(contributions)
    ratio = agreement_count / total if total > 0 else 0.0
    quorum_met = ratio > config.quorum_ratio

    return QuorumResult(
        quorum_met=quorum_met,
        agreement_count=agreement_count,
        total_reporters=total,
        agreement_ratio=round(ratio, 6),
    )


def build_score_summary(contributions: tuple[PeerContribution, ...]) -> ScoreSummary:
    scores = tuple(c.score for c in contributions)
    return ScoreSummary(
        avg_score=round(sum(scores) / len(scores), 6) if scores else 0.0,
        min_score=min(scores) if scores else 0.0,
        max_score=max(scores) if scores else 0.0,
        endorsements=sum(1 for c in contributions if c.status == "endorse"),
        flags=sum(1 for c in contributions if c.status in ("flag", "jail")),
        total_reporters=len(contributions),
    )


def load_consensus_summary(summary_json: dict[str, Any]) -> list[dict[str, Any]]:
    entries = summary_json.get("consensus_entries")
    if not isinstance(entries, list):
        raise ValueError("consensus summary must contain a consensus_entries array")
    return entries


def _derive_status_from_score(score: float, recommended_action: str) -> str:
    if recommended_action == "escalate":
        return "jail"
    if recommended_action == "warn":
        return "flag" if score < 0 else "endorse"
    return "endorse"


def build_amendment_proposals(
    consensus_entries: list[dict[str, Any]],
    peer_signatures: dict[str, str],
    config: AmendmentConfig,
    *,
    proposing_validator: str,
) -> list[AmendmentProposal]:
    proposals: list[AmendmentProposal] = []
    for entry in consensus_entries:
        reporters = entry.get("reporters", [])
        scores = entry.get("scores", [])
        recommended_action = str(entry.get("recommended_action", "maintain")).strip()
        target = str(entry.get("target_address", "")).strip()
        if not target:
            continue

        amendment_action = map_consensus_action_to_amendment(recommended_action)

        contributions: list[PeerContribution] = []
        for i, reporter in enumerate(reporters):
            score = scores[i] if i < len(scores) else 0.0
            status = _derive_status_from_score(score, recommended_action)
            sig = peer_signatures.get(reporter, "")
            contributions.append(PeerContribution(reporter, score, status, sig))

        contributions_tuple = tuple(contributions)
        quorum_result = evaluate_quorum(amendment_action, contributions_tuple, config)
        score_summary = build_score_summary(contributions_tuple)

        proposals.append(
            AmendmentProposal(
                amendment_action=amendment_action,
                target_validator_public_key=target,
                quorum_met=quorum_result.quorum_met,
                agreement_ratio=quorum_result.agreement_ratio,
                contributing_peers=contributions_tuple,
                score_summary=score_summary,
                proposed_at=format_utc(utc_now()),
                proposing_validator_public_key=proposing_validator,
            )
        )

    return proposals


def amendment_proposal_to_dict(proposal: AmendmentProposal) -> dict[str, Any]:
    return {
        "amendment_action": proposal.amendment_action,
        "target_validator_public_key": proposal.target_validator_public_key,
        "quorum_met": proposal.quorum_met,
        "agreement_ratio": proposal.agreement_ratio,
        "contributing_peers": [
            {
                "validator_public_key": c.validator_public_key,
                "score": c.score,
                "status": c.status,
                "signature": c.signature,
            }
            for c in proposal.contributing_peers
        ],
        "score_summary": {
            "avg_score": proposal.score_summary.avg_score,
            "min_score": proposal.score_summary.min_score,
            "max_score": proposal.score_summary.max_score,
            "endorsements": proposal.score_summary.endorsements,
            "flags": proposal.score_summary.flags,
            "total_reporters": proposal.score_summary.total_reporters,
        },
        "proposed_at": proposal.proposed_at,
        "proposing_validator_public_key": proposal.proposing_validator_public_key,
    }


def build_amendment_memo_payload(proposal: AmendmentProposal) -> dict[str, Any]:
    payload = amendment_proposal_to_dict(proposal)
    payload["schema"] = DEFAULT_AMENDMENT_SCHEMA
    return payload


def sign_amendment_proposal(
    proposal: AmendmentProposal,
    signing_key: nacl.signing.SigningKey,
) -> SignedAmendmentProposal:
    payload = build_amendment_memo_payload(proposal)
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = signing_key.sign(canonical_json.encode("utf-8")).signature.hex().upper()
    signed_payload = dict(payload, proposal_signature=signature)
    signed_payload_json = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))

    compressed = zlib.compress(signed_payload_json.encode("utf-8"), level=9)
    memo_hex = compressed.hex().upper()

    return SignedAmendmentProposal(
        proposal=proposal,
        signed_payload=signed_payload,
        memo=Memo(
            memo_data=memo_hex,
            memo_format=encode_memo_field("application/json+zlib"),
            memo_type=encode_memo_field(DEFAULT_AMENDMENT_SCHEMA),
        ),
        memo_hex=memo_hex,
        proposal_signature=signature,
    )


SIMULATED_TARGETS = [
    "nHTargetHealthyAAA111111111111111111111111111",
    "nHTargetMixedBBBB222222222222222222222222222",
    "nHTargetBadCCCCCC333333333333333333333333333",
    "nHTargetSplitDDDD444444444444444444444444444",
]

SIMULATED_GRID = [
    {"score": 0.9, "status": "endorse"},
    {"score": 0.85, "status": "endorse"},
    {"score": 0.95, "status": "endorse"},
    {"score": 0.3, "status": "flag"},
    {"score": 0.4, "status": "flag"},
    {"score": 0.2, "status": "flag"},
    {"score": -0.8, "status": "jail"},
    {"score": -0.9, "status": "jail"},
    {"score": -0.7, "status": "jail"},
    {"score": 0.9, "status": "endorse"},
    {"score": -0.5, "status": "flag"},
    {"score": 0.2, "status": "endorse"},
]


def _action_from_scores(scores: list[float], statuses: list[str]) -> str:
    avg = sum(scores) / len(scores) if scores else 0.0
    flags = sum(1 for s in statuses if s in ("flag", "jail"))
    if flags == len(statuses) and avg < -0.5:
        return "escalate"
    if flags > 0:
        return "warn"
    return "maintain"


def generate_simulation() -> dict[str, Any]:
    validators = []
    for i in range(3):
        sk = nacl.signing.SigningKey.generate()
        pub_key = addresscodec.encode_node_public_key(b"\xed" + bytes(sk.verify_key))
        canonical = json.dumps({"validator": pub_key, "idx": i}, sort_keys=True, separators=(",", ":"))
        sig = sk.sign(canonical.encode("utf-8")).signature.hex().upper()
        validators.append({
            "signing_key": sk,
            "validator_public_key": pub_key,
            "signature_hex": sig,
        })

    peer_signatures = {v["validator_public_key"]: v["signature_hex"] for v in validators}

    consensus_entries = []
    for t_idx, target in enumerate(SIMULATED_TARGETS):
        scores = []
        reporters = []
        statuses = []
        for v_idx in range(3):
            grid_idx = t_idx * 3 + v_idx
            entry = SIMULATED_GRID[grid_idx]
            scores.append(entry["score"])
            reporters.append(validators[v_idx]["validator_public_key"])
            statuses.append(entry["status"])

        action = _action_from_scores(scores, statuses)
        avg_score = round(sum(scores) / len(scores), 6)
        consensus_entries.append({
            "target_address": target,
            "reporters": reporters,
            "scores": scores,
            "avg_score": avg_score,
            "min_score": min(scores),
            "max_score": max(scores),
            "endorsements": sum(1 for s in statuses if s == "endorse"),
            "flags": sum(1 for s in statuses if s in ("flag", "jail")),
            "recommended_action": action,
            "threshold_reason": f"{action} from simulation",
        })

    return {
        "validators": [{k: v for k, v in val.items() if k != "signing_key"} for val in validators],
        "validators_with_keys": validators,
        "consensus_entries": consensus_entries,
        "peer_signatures": peer_signatures,
    }


def render_ingestion(consensus_entries: list[dict[str, Any]], *, mode: str) -> None:
    print("=" * 72)
    print("UNL Amendment Proposal Module")
    print("=" * 72)
    print(
        f"[INGEST] mode={mode} "
        f"consensus_entries={len(consensus_entries)}"
    )
    for entry in consensus_entries:
        reporters = entry.get("reporters", [])
        scores = entry.get("scores", [])
        print(
            f"[INGEST] target={entry.get('target_address', 'n/a')} "
            f"reporters={len(reporters)} "
            f"scores={[round(s, 2) for s in scores]} "
            f"recommended_action={entry.get('recommended_action', 'n/a')}"
        )
    print()


def render_quorum_evaluation(proposals: list[AmendmentProposal]) -> None:
    print("=" * 72)
    print("Quorum Evaluation")
    print("=" * 72)
    for proposal in proposals:
        status = "PASSED" if proposal.quorum_met else "FAILED"
        print(
            f"[QUORUM] target={proposal.target_validator_public_key} "
            f"amendment_action={proposal.amendment_action} "
            f"agreement_ratio={proposal.agreement_ratio:.4f} "
            f"threshold>{DEFAULT_QUORUM_RATIO:.4f} "
            f"quorum={status} "
            f"peers={len(proposal.contributing_peers)}"
        )
        for peer in proposal.contributing_peers:
            sig_display = peer.signature[:12] + "..." if len(peer.signature) > 12 else peer.signature
            print(
                f"[QUORUM]   peer={peer.validator_public_key[:20]}... "
                f"score={peer.score:.3f} "
                f"status={peer.status} "
                f"signature={sig_display}"
            )
        print(
            f"[QUORUM]   score_summary: "
            f"avg={proposal.score_summary.avg_score:.3f} "
            f"min={proposal.score_summary.min_score:.3f} "
            f"max={proposal.score_summary.max_score:.3f} "
            f"endorsements={proposal.score_summary.endorsements} "
            f"flags={proposal.score_summary.flags}"
        )
    print()


def render_proposals(signed_proposals: list[SignedAmendmentProposal], *, dry_run: bool) -> None:
    print("=" * 72)
    print("Amendment Proposals")
    print("=" * 72)
    for sp in signed_proposals:
        p = sp.proposal
        print(
            f"[PROPOSAL] target={p.target_validator_public_key} "
            f"action={p.amendment_action} "
            f"quorum_met={p.quorum_met} "
            f"agreement_ratio={p.agreement_ratio:.4f} "
            f"contributing_peers={len(p.contributing_peers)}"
        )
        print(f"[MEMO] schema={DEFAULT_AMENDMENT_SCHEMA}")
        print(json.dumps(sp.signed_payload, indent=2))
        print(f"[MEMO] memo_data_hex={sp.memo_hex}")
        print(f"[MEMO] proposal_signature={sp.proposal_signature}")
        print()


def render_dry_run_results(
    signed_proposals: list[SignedAmendmentProposal],
    dry_run_results: list[Any],
) -> None:
    print("=" * 72)
    print("Dry-Run Transaction Results")
    print("=" * 72)
    for sp, signed_tx in zip(signed_proposals, dry_run_results):
        p = sp.proposal
        if signed_tx is not None:
            print(
                f"[DRY_RUN] target={p.target_validator_public_key} "
                f"action={p.amendment_action} "
                f"signed_tx_hash={signed_tx.get_hash()}"
            )
        else:
            print(
                f"[DRY_RUN] target={p.target_validator_public_key} "
                f"action={p.amendment_action} "
                f"status=skipped_quorum_not_met"
            )
        print()


def render_submit_results(
    signed_proposals: list[SignedAmendmentProposal],
    submit_results: list[dict[str, Any]],
) -> None:
    print("=" * 72)
    print("Submission Results")
    print("=" * 72)
    for sp, result in zip(signed_proposals, submit_results):
        p = sp.proposal
        print(
            f"[SUBMIT] target={p.target_validator_public_key} "
            f"action={p.amendment_action} "
            f"transaction_hash={result.get('transaction_hash', 'n/a')} "
            f"engine_result={result.get('engine_result', 'n/a')}"
        )
        print(json.dumps(result.get("result", {}), indent=2, default=str))
        print()


def run_amendment_pipeline(
    consensus_entries: list[dict[str, Any]],
    peer_signatures: dict[str, str],
    proposing_validator: str,
    signing_key: nacl.signing.SigningKey,
    config: AmendmentConfig,
    *,
    client: Optional[JsonRpcClient] = None,
    wallet_context: Optional[FeePayerContext] = None,
    dry_run: bool = True,
    mode: str = "simulate",
) -> int:
    render_ingestion(consensus_entries, mode=mode)

    proposals = build_amendment_proposals(
        consensus_entries, peer_signatures, config,
        proposing_validator=proposing_validator,
    )
    render_quorum_evaluation(proposals)

    quorum_met_proposals = [p for p in proposals if p.quorum_met]
    if not quorum_met_proposals:
        print("[RESULT] No amendment proposals met the quorum threshold")
        return 0

    signed_proposals = [sign_amendment_proposal(p, signing_key) for p in quorum_met_proposals]
    render_proposals(signed_proposals, dry_run=dry_run)

    if dry_run and client is not None and wallet_context is not None:
        dry_run_results = []
        for sp in signed_proposals:
            try:
                signed_tx, _metadata, _seq_src = build_dry_run_transaction(
                    client, wallet_context, sp.memo
                )
                dry_run_results.append(signed_tx)
            except Exception:
                dry_run_results.append(None)
        render_dry_run_results(signed_proposals, dry_run_results)
    elif not dry_run and client is not None and wallet_context is not None:
        submit_results = []
        for sp in signed_proposals:
            result = submit_vote_transaction(client, wallet_context, sp.memo)
            submit_results.append(result)
        render_submit_results(signed_proposals, submit_results)

    print("=" * 72)
    print(f"[RESULT] proposals_total={len(proposals)} "
          f"quorum_met={len(quorum_met_proposals)} "
          f"quorum_failed={len(proposals) - len(quorum_met_proposals)}")
    return 0


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build consensus-driven UNL amendment proposals and submit as XRPL memo transactions"
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--simulate", action="store_true", help="Run with simulated 3-validator consensus state")
    parser.add_argument("--input", help="Path to consensus summary JSON from health_signature_ingestion.py")
    parser.add_argument("--submit", action="store_true", help="Submit transactions to XRPL testnet")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Dry-run mode (default)")
    parser.add_argument("--json-out", help="Write proposals as JSON to this path")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if not args.simulate and not args.input:
        parser.error("either --simulate or --input is required")

    try:
        config = AmendmentConfig()

        if args.simulate:
            sim = generate_simulation()
            consensus_entries = sim["consensus_entries"]
            peer_signatures = sim["peer_signatures"]
            proposing_validator = sim["validators"][0]["validator_public_key"]
            signing_key = sim["validators_with_keys"][0]["signing_key"]
            mode = "simulate"
        else:
            input_path = Path(args.input)
            if not input_path.exists():
                print(f"Input file not found: {input_path}", file=sys.stderr)
                return 1
            summary_json = json.loads(input_path.read_text())
            consensus_entries = load_consensus_summary(summary_json)
            voting_config = load_voting_config(Path(args.config))
            identity = load_validator_identity(voting_config.validator_keys_path)
            proposing_validator = identity.validator_public_key
            peer_signatures = {}
            for entry in consensus_entries:
                for reporter in entry.get("reporters", []):
                    if reporter not in peer_signatures:
                        peer_signatures[reporter] = ""
            mode = "live"
            signing_key = nacl.signing.SigningKey.generate()

        dry_run = not args.submit

        client = None
        wallet_context = None
        if args.simulate:
            client = JsonRpcClient(TESTNET_RPC_URL)
            wallet_context = FeePayerContext(
                wallet=Wallet.create(algorithm=CryptoAlgorithm.ED25519),
                source="generated_ephemeral_dry_run_wallet",
            )
        else:
            voting_config = load_voting_config(Path(args.config))
            client = JsonRpcClient(voting_config.xrpl_rpc_url)
            wallet_context = resolve_fee_payer_wallet(voting_config, allow_ephemeral=dry_run)

        result = run_amendment_pipeline(
            consensus_entries, peer_signatures, proposing_validator, signing_key, config,
            client=client, wallet_context=wallet_context, dry_run=dry_run, mode=mode,
        )

        if args.json_out:
            all_proposals = build_amendment_proposals(
                consensus_entries, peer_signatures, config,
                proposing_validator=proposing_validator,
            )
            proposals_data = [amendment_proposal_to_dict(p) for p in all_proposals]
            output_data = {
                "generated_at": format_utc(utc_now()),
                "proposals": proposals_data,
                "schema": DEFAULT_AMENDMENT_SCHEMA,
            }
            Path(args.json_out).write_text(json.dumps(output_data, indent=2))
            print(f"[OUTPUT] json_path={args.json_out}")

        return result

    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
