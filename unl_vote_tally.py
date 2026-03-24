#!/usr/bin/env python3
"""
Deterministic UNL vote aggregation and tally module for PostFiat validators.

The module ingests signed UNL vote memos either from direct JSON payloads or
XRPL transaction JSON, tallies flag/endorse decisions per target validator, and
prints a deterministic UNL health report with recommended actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DEFAULT_MEMO_SCHEMA = "postfiat.unl_vote.v1"
DEFAULT_MEMO_FORMAT = "application/json"
DEFAULT_QUORUM_RATIO = 0.5
DEFAULT_WARN_FLAG_RATIO = 0.5
DEFAULT_JAIL_FLAG_RATIO = 2 / 3


@dataclass(frozen=True)
class TallyConfig:
    quorum_ratio: float = DEFAULT_QUORUM_RATIO
    warn_flag_ratio: float = DEFAULT_WARN_FLAG_RATIO
    jail_flag_ratio: float = DEFAULT_JAIL_FLAG_RATIO
    active_validator_count: Optional[int] = None


@dataclass(frozen=True)
class VoteMemoRecord:
    voter_validator_address: str
    target_validator_address: str
    decision: str
    timestamp: datetime
    signature: str
    schema: str
    tx_hash: Optional[str]
    source: str


@dataclass(frozen=True)
class ValidatorTally:
    target_validator_address: str
    flag_votes: int
    endorse_votes: int
    total_votes: int
    voters_participating: int
    active_validator_count: int
    participation_ratio: float
    flag_ratio: float
    endorse_ratio: float
    quorum_met: bool
    recommended_action: str
    threshold_reason: str


@dataclass(frozen=True)
class UnlHealthReport:
    ingested_vote_count: int
    deduped_vote_count: int
    active_validator_count: int
    tallies: tuple[ValidatorTally, ...]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc_timestamp(name: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty ISO 8601 timestamp")

    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid ISO 8601 timestamp") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def normalize_ratio(name: str, value: Any) -> float:
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc

    if normalized > 1:
        normalized /= 100.0

    if normalized < 0 or normalized > 1:
        raise ValueError(f"{name} must normalize into the range 0..1")

    return round(normalized, 6)


def encode_memo_field(value: str) -> str:
    return value.encode("utf-8").hex().upper()


def decode_memo_field(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty hex string")

    stripped = value.strip()
    try:
        decoded = bytes.fromhex(stripped)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hexadecimal") from exc

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must decode as UTF-8") from exc


def first_non_empty(payload: dict[str, Any], field_names: tuple[str, ...], label: str) -> str:
    for field_name in field_names:
        value = payload.get(field_name)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    raise ValueError(f"{label} is required")


def normalize_decision(value: Any) -> str:
    decision = str(value).strip().lower()
    if decision not in {"flag", "endorse"}:
        raise ValueError("decision must be either 'flag' or 'endorse'")
    return decision


def looks_like_vote_payload(raw_record: dict[str, Any]) -> bool:
    decision_fields = {"decision", "verdict"}
    target_fields = {"peer_validator_public_key", "target_validator_address", "target_peer", "target_validator"}
    voter_fields = {
        "voter_validator_public_key",
        "validator_address",
        "validator_public_key",
        "validator",
        "voter",
    }

    return bool(decision_fields & raw_record.keys()) and bool(target_fields & raw_record.keys()) and bool(
        voter_fields & raw_record.keys()
    )


def parse_vote_payload(payload: dict[str, Any], *, tx_hash: Optional[str], source: str) -> VoteMemoRecord:
    schema = str(payload.get("schema", DEFAULT_MEMO_SCHEMA)).strip()
    if schema != DEFAULT_MEMO_SCHEMA:
        raise ValueError(f"unsupported memo schema '{schema}'")

    voter = first_non_empty(
        payload,
        ("voter_validator_public_key", "validator_address", "validator_public_key", "validator", "voter"),
        "validator address",
    )
    target = first_non_empty(
        payload,
        ("peer_validator_public_key", "target_validator_address", "target_peer", "target_validator"),
        "target peer",
    )
    decision = normalize_decision(payload.get("verdict", payload.get("decision")))
    timestamp = parse_utc_timestamp("timestamp", payload.get("evaluated_at", payload.get("timestamp")))
    signature = first_non_empty(payload, ("validator_signature", "signature"), "signature")

    return VoteMemoRecord(
        voter_validator_address=voter,
        target_validator_address=target,
        decision=decision,
        timestamp=timestamp,
        signature=signature,
        schema=schema,
        tx_hash=tx_hash,
        source=source,
    )


def parse_xrpl_memo_payload(memo: dict[str, Any]) -> Optional[dict[str, Any]]:
    data_hex = memo.get("MemoData", memo.get("memo_data"))
    if not data_hex:
        return None

    memo_type_hex = memo.get("MemoType", memo.get("memo_type"))
    if memo_type_hex:
        memo_type = decode_memo_field("MemoType", memo_type_hex)
        if memo_type != DEFAULT_MEMO_SCHEMA:
            return None

    memo_data_text = decode_memo_field("MemoData", data_hex)
    try:
        payload = json.loads(memo_data_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"MemoData did not decode into JSON ({exc.msg})") from exc

    if not isinstance(payload, dict):
        raise ValueError("MemoData must decode into a JSON object")

    return payload


def extract_vote_payloads(raw_record: dict[str, Any], record_index: int) -> list[tuple[dict[str, Any], Optional[str], str]]:
    payloads: list[tuple[dict[str, Any], Optional[str], str]] = []

    tx_hash = str(raw_record.get("hash") or raw_record.get("tx_hash") or "").strip() or None

    if looks_like_vote_payload(raw_record):
        payloads.append((raw_record, tx_hash, f"record[{record_index}]"))

    memo_payload = raw_record.get("memo_payload")
    if isinstance(memo_payload, dict):
        payloads.append((memo_payload, tx_hash, f"record[{record_index}].memo_payload"))

    tx_container = raw_record.get("tx") if isinstance(raw_record.get("tx"), dict) else raw_record
    memos = tx_container.get("Memos") or tx_container.get("memos")
    if isinstance(memos, list):
        tx_hash = tx_hash or str(tx_container.get("hash") or "").strip() or None
        for memo_index, memo_wrapper in enumerate(memos, start=1):
            if not isinstance(memo_wrapper, dict):
                continue
            memo = memo_wrapper.get("Memo") if isinstance(memo_wrapper.get("Memo"), dict) else memo_wrapper
            if not isinstance(memo, dict):
                continue
            payload = parse_xrpl_memo_payload(memo)
            if payload is not None:
                payloads.append((payload, tx_hash, f"record[{record_index}].memo[{memo_index}]"))

    if not payloads:
        raise ValueError("record did not contain a vote payload or XRPL vote memo")

    return payloads


def load_raw_records(input_path: Path) -> list[Any]:
    raw_text = input_path.read_text().strip()
    if not raw_text:
        return []

    if raw_text.lstrip().startswith("["):
        parsed = json.loads(raw_text)
        if not isinstance(parsed, list):
            raise ValueError("JSON input must contain an array of vote transactions")
        return parsed

    if raw_text.lstrip().startswith("{"):
        parsed = json.loads(raw_text)
        if isinstance(parsed, dict) and isinstance(parsed.get("transactions"), list):
            return parsed["transactions"]
        return [parsed]

    raw_records: list[Any] = []
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            raw_records.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number} was not valid JSON ({exc.msg})") from exc

    return raw_records


def load_vote_transactions(input_path: Path) -> tuple[list[VoteMemoRecord], list[str]]:
    raw_records = load_raw_records(input_path)
    votes: list[VoteMemoRecord] = []
    warnings: list[str] = []

    for record_index, raw_record in enumerate(raw_records, start=1):
        if not isinstance(raw_record, dict):
            warnings.append(f"Skipped record {record_index}: expected an object")
            continue
        try:
            payloads = extract_vote_payloads(raw_record, record_index)
            for payload, tx_hash, source in payloads:
                votes.append(parse_vote_payload(payload, tx_hash=tx_hash, source=source))
        except (TypeError, ValueError, KeyError) as exc:
            warnings.append(f"Skipped record {record_index}: {exc}")

    return votes, warnings


def vote_identity_key(vote: VoteMemoRecord) -> tuple[str, str]:
    return vote.target_validator_address, vote.voter_validator_address


def vote_sort_key(vote: VoteMemoRecord) -> tuple[str, str, str, str, str, str]:
    return (
        vote.target_validator_address,
        vote.voter_validator_address,
        format_utc(vote.timestamp),
        vote.decision,
        vote.signature,
        vote.tx_hash or vote.source,
    )


def vote_precedence_key(vote: VoteMemoRecord) -> tuple[str, str, str, str]:
    return (
        format_utc(vote.timestamp),
        vote.decision,
        vote.signature,
        vote.tx_hash or vote.source,
    )


def deduplicate_latest_votes(votes: list[VoteMemoRecord]) -> list[VoteMemoRecord]:
    latest_votes: dict[tuple[str, str], VoteMemoRecord] = {}

    for vote in sorted(votes, key=vote_sort_key):
        existing = latest_votes.get(vote_identity_key(vote))
        if existing is None or vote_precedence_key(vote) >= vote_precedence_key(existing):
            latest_votes[vote_identity_key(vote)] = vote

    return sorted(latest_votes.values(), key=vote_sort_key)


def resolve_active_validator_count(votes: list[VoteMemoRecord], config: TallyConfig) -> int:
    observed_voters = {vote.voter_validator_address for vote in votes}
    observed_count = len(observed_voters)

    if config.active_validator_count is None:
        return observed_count

    if config.active_validator_count < observed_count:
        raise ValueError(
            "active validator count override cannot be lower than the number of observed validator votes"
        )

    return config.active_validator_count


def build_threshold_reason(
    *,
    flag_ratio: float,
    participation_ratio: float,
    quorum_met: bool,
    config: TallyConfig,
) -> tuple[str, str]:
    if not quorum_met:
        return (
            "maintain",
            "quorum missed: participation "
            f"{format_ratio(participation_ratio)} <= quorum threshold {format_ratio(config.quorum_ratio)}",
        )

    if flag_ratio > config.jail_flag_ratio:
        return (
            "jail",
            "jail threshold met: flag ratio "
            f"{format_ratio(flag_ratio)} > {format_ratio(config.jail_flag_ratio)} with participation "
            f"{format_ratio(participation_ratio)} > {format_ratio(config.quorum_ratio)}",
        )

    if flag_ratio >= config.warn_flag_ratio:
        return (
            "warn",
            "warn threshold met: flag ratio "
            f"{format_ratio(flag_ratio)} >= {format_ratio(config.warn_flag_ratio)} with participation "
            f"{format_ratio(participation_ratio)} > {format_ratio(config.quorum_ratio)}",
        )

    return (
        "maintain",
        "maintain threshold met: flag ratio "
        f"{format_ratio(flag_ratio)} < warn threshold {format_ratio(config.warn_flag_ratio)}",
    )


def aggregate_votes(votes: list[VoteMemoRecord], config: TallyConfig) -> UnlHealthReport:
    deduped_votes = deduplicate_latest_votes(votes)
    active_validator_count = resolve_active_validator_count(deduped_votes, config)

    votes_by_target: dict[str, list[VoteMemoRecord]] = {}
    for vote in deduped_votes:
        votes_by_target.setdefault(vote.target_validator_address, []).append(vote)

    tallies: list[ValidatorTally] = []
    for target in sorted(votes_by_target):
        target_votes = sorted(votes_by_target[target], key=vote_sort_key)
        flag_votes = sum(1 for vote in target_votes if vote.decision == "flag")
        endorse_votes = sum(1 for vote in target_votes if vote.decision == "endorse")
        total_votes = flag_votes + endorse_votes
        voters_participating = len({vote.voter_validator_address for vote in target_votes})
        participation_ratio = voters_participating / active_validator_count if active_validator_count else 0.0
        flag_ratio = flag_votes / total_votes if total_votes else 0.0
        endorse_ratio = endorse_votes / total_votes if total_votes else 0.0
        quorum_met = participation_ratio > config.quorum_ratio
        recommended_action, threshold_reason = build_threshold_reason(
            flag_ratio=flag_ratio,
            participation_ratio=participation_ratio,
            quorum_met=quorum_met,
            config=config,
        )

        tallies.append(
            ValidatorTally(
                target_validator_address=target,
                flag_votes=flag_votes,
                endorse_votes=endorse_votes,
                total_votes=total_votes,
                voters_participating=voters_participating,
                active_validator_count=active_validator_count,
                participation_ratio=participation_ratio,
                flag_ratio=flag_ratio,
                endorse_ratio=endorse_ratio,
                quorum_met=quorum_met,
                recommended_action=recommended_action,
                threshold_reason=threshold_reason,
            )
        )

    return UnlHealthReport(
        ingested_vote_count=len(votes),
        deduped_vote_count=len(deduped_votes),
        active_validator_count=active_validator_count,
        tallies=tuple(tallies),
    )


def format_ratio(value: float) -> str:
    return f"{value * 100:.2f}%"


def shorten_signature(signature: str, *, head: int = 12) -> str:
    if len(signature) <= head:
        return signature
    return f"{signature[:head]}..."


def render_ingestion(votes: list[VoteMemoRecord], warnings: list[str], report: UnlHealthReport) -> None:
    print("=" * 72)
    print("UNL Vote Aggregation and Tally")
    print("=" * 72)
    print(
        "[INGEST] "
        f"valid_vote_memos={report.ingested_vote_count} "
        f"deduped_votes={report.deduped_vote_count} "
        f"active_validators={report.active_validator_count} "
        f"warnings={len(warnings)}"
    )
    for warning in warnings:
        print(f"[WARN] {warning}")

    for vote in sorted(votes, key=vote_sort_key):
        print(
            "[INGEST] "
            f"tx={vote.tx_hash or 'n/a'} "
            f"voter={vote.voter_validator_address} "
            f"target={vote.target_validator_address} "
            f"decision={vote.decision} "
            f"timestamp={format_utc(vote.timestamp)} "
            f"signature={shorten_signature(vote.signature)}"
        )

    print()


def render_tallies(report: UnlHealthReport) -> None:
    print("[TALLY] per-validator vote counts")
    for tally in report.tallies:
        print(
            "[TALLY] "
            f"target={tally.target_validator_address} "
            f"flags={tally.flag_votes} "
            f"endorses={tally.endorse_votes} "
            f"votes={tally.total_votes} "
            f"participants={tally.voters_participating}/{tally.active_validator_count} "
            f"quorum={'met' if tally.quorum_met else 'missed'} "
            f"flag_ratio={format_ratio(tally.flag_ratio)} "
            f"endorse_ratio={format_ratio(tally.endorse_ratio)}"
        )

    print()


def render_report(report: UnlHealthReport, config: TallyConfig) -> None:
    print("[REPORT] deterministic UNL health report")
    print(
        "[REPORT] "
        f"quorum_threshold>{format_ratio(config.quorum_ratio)} "
        f"warn_threshold>={format_ratio(config.warn_flag_ratio)} "
        f"jail_threshold>{format_ratio(config.jail_flag_ratio)}"
    )
    for tally in report.tallies:
        print(
            "[REPORT] "
            f"target={tally.target_validator_address} "
            f"action={tally.recommended_action} "
            f"flags={tally.flag_votes} "
            f"endorses={tally.endorse_votes} "
            f"participation={format_ratio(tally.participation_ratio)} "
            f"flag_ratio={format_ratio(tally.flag_ratio)} "
            f"reason={tally.threshold_reason}"
        )


def build_simulated_signed_payload(
    *,
    voter: str,
    target: str,
    decision: str,
    timestamp: str,
    signature_seed: str,
) -> dict[str, Any]:
    signature = signature_seed * 64
    breaches = ["health_threshold_breach"] if decision == "flag" else []
    metrics_digest = hashlib.sha256(f"{voter}|{target}|{decision}|{timestamp}".encode("utf-8")).hexdigest()
    return {
        "schema": DEFAULT_MEMO_SCHEMA,
        "peer_validator_public_key": target,
        "verdict": decision,
        "evaluated_at": timestamp,
        "breaches": breaches,
        "voter_validator_public_key": voter,
        "metrics_digest_sha256": metrics_digest,
        "validator_signature": signature,
    }


def build_simulated_transaction(*, tx_hash: str, payload: dict[str, Any], ledger_index: int) -> dict[str, Any]:
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "hash": tx_hash,
        "ledger_index": ledger_index,
        "validated": True,
        "tx": {
            "TransactionType": "AccountSet",
            "Account": f"rFeePayer{ledger_index}",
            "Memos": [
                {
                    "Memo": {
                        "MemoType": encode_memo_field(DEFAULT_MEMO_SCHEMA),
                        "MemoFormat": encode_memo_field(DEFAULT_MEMO_FORMAT),
                        "MemoData": encode_memo_field(payload_json),
                    }
                }
            ],
        },
    }


def build_simulated_vote_transactions() -> list[dict[str, Any]]:
    simulated_votes = [
        (
            "SIMTX001",
            build_simulated_signed_payload(
                voter="nHValidatorAlpha11111111111111111111111111",
                target="nHTargetPeerRed11111111111111111111111111",
                decision="flag",
                timestamp="2026-03-24T00:01:00Z",
                signature_seed="A1",
            ),
        ),
        (
            "SIMTX002",
            build_simulated_signed_payload(
                voter="nHValidatorBeta22222222222222222222222222",
                target="nHTargetPeerRed11111111111111111111111111",
                decision="flag",
                timestamp="2026-03-24T00:02:00Z",
                signature_seed="B2",
            ),
        ),
        (
            "SIMTX003",
            build_simulated_signed_payload(
                voter="nHValidatorGamma3333333333333333333333333",
                target="nHTargetPeerRed11111111111111111111111111",
                decision="flag",
                timestamp="2026-03-24T00:03:00Z",
                signature_seed="C3",
            ),
        ),
        (
            "SIMTX004",
            build_simulated_signed_payload(
                voter="nHValidatorAlpha11111111111111111111111111",
                target="nHTargetPeerBlue2222222222222222222222222",
                decision="endorse",
                timestamp="2026-03-24T00:04:00Z",
                signature_seed="D4",
            ),
        ),
        (
            "SIMTX005",
            build_simulated_signed_payload(
                voter="nHValidatorBeta22222222222222222222222222",
                target="nHTargetPeerBlue2222222222222222222222222",
                decision="endorse",
                timestamp="2026-03-24T00:05:00Z",
                signature_seed="E5",
            ),
        ),
        (
            "SIMTX006",
            build_simulated_signed_payload(
                voter="nHValidatorDelta4444444444444444444444444",
                target="nHTargetPeerBlue2222222222222222222222222",
                decision="flag",
                timestamp="2026-03-24T00:06:00Z",
                signature_seed="F6",
            ),
        ),
    ]

    return [
        build_simulated_transaction(tx_hash=tx_hash, payload=payload, ledger_index=900000 + index)
        for index, (tx_hash, payload) in enumerate(simulated_votes, start=1)
    ]


def write_simulated_dataset() -> Path:
    output_path = Path(__file__).with_name("sample_unl_vote_transactions.json")
    output_path.write_text(json.dumps(build_simulated_vote_transactions(), indent=2))
    return output_path


def load_simulated_votes() -> tuple[list[VoteMemoRecord], list[str], Path]:
    dataset_path = write_simulated_dataset()
    votes, warnings = load_vote_transactions(dataset_path)
    return votes, warnings, dataset_path


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate signed UNL vote memos into a deterministic health report")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", help="Path to JSON or JSONL with direct vote payloads or XRPL tx objects")
    input_group.add_argument("--simulate", action="store_true", help="Use the built-in simulated UNL vote dataset")

    parser.add_argument(
        "--active-validator-count",
        type=int,
        help="Override the active validator denominator used to compute quorum",
    )
    parser.add_argument("--quorum-ratio", default=str(DEFAULT_QUORUM_RATIO), help="Quorum ratio as 0..1 or 0..100")
    parser.add_argument(
        "--warn-flag-ratio",
        default=str(DEFAULT_WARN_FLAG_RATIO),
        help="Warn threshold as 0..1 or 0..100",
    )
    parser.add_argument(
        "--jail-flag-ratio",
        default=str(DEFAULT_JAIL_FLAG_RATIO),
        help="Jail threshold as 0..1 or 0..100",
    )

    return parser


def validate_tally_config(config: TallyConfig) -> None:
    if config.warn_flag_ratio > config.jail_flag_ratio:
        raise ValueError("warn flag ratio cannot be greater than jail flag ratio")
    if config.active_validator_count is not None and config.active_validator_count <= 0:
        raise ValueError("active validator count must be greater than zero")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = TallyConfig(
            quorum_ratio=normalize_ratio("quorum_ratio", args.quorum_ratio),
            warn_flag_ratio=normalize_ratio("warn_flag_ratio", args.warn_flag_ratio),
            jail_flag_ratio=normalize_ratio("jail_flag_ratio", args.jail_flag_ratio),
            active_validator_count=args.active_validator_count,
        )
        validate_tally_config(config)

        if args.simulate:
            votes, warnings, dataset_path = load_simulated_votes()
            print(f"[INGEST] simulation_dataset={dataset_path}")
        else:
            input_path = Path(args.input)
            if not input_path.exists():
                print(f"Input file not found: {input_path}", file=sys.stderr)
                return 1
            votes, warnings = load_vote_transactions(input_path)
            print(f"[INGEST] input_path={input_path}")

        if not votes:
            print("No valid vote transactions were found for tallying", file=sys.stderr)
            return 1

        report = aggregate_votes(votes, config)
        render_ingestion(votes, warnings, report)
        render_tallies(report)
        render_report(report, config)
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
