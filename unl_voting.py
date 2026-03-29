#!/usr/bin/env python3
"""
UNL peer health voting transaction builder for PostFiat validators.

Reads peer scoring logs, evaluates health thresholds, signs a compact vote memo
with the validator's Ed25519 keypair, and builds XRPL Payment transactions that
carry the governance decision on-ledger.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import nacl.exceptions
import nacl.signing
from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.core import addresscodec
from xrpl.models.requests import AccountInfo, ServerInfo
from xrpl.models.transactions import AccountSet, Memo
from xrpl.transaction import sign, submit_and_wait
from xrpl.wallet import Wallet

DEFAULT_CONFIG_PATH = Path("/home/postfiat/peer-defense/config.json")
DEFAULT_SAMPLE_PATH = Path(__file__).with_name("sample_peer_scores.json")
DEFAULT_MEMO_SCHEMA = "postfiat.unl_vote.v1"
DEFAULT_MEMO_FORMAT = "application/json"
DEFAULT_FEE_DROPS = "10"
DEFAULT_LEDGER_BUFFER = 20


@dataclass(frozen=True)
class VotingConfig:
    uptime_min_pct: float
    latency_max_ms: int
    consensus_min_pct: float
    last_seen_max_age_seconds: int
    xrpl_rpc_url: str
    validator_keys_path: Path
    fee_payer_seed_env: str
    dry_run_default: bool


@dataclass(frozen=True)
class PeerScoreRecord:
    validator_public_key: str
    uptime_pct: float
    scoring_latency_ms: int
    consensus_participation_pct: float
    last_seen_utc: datetime
    collected_at: Optional[datetime]


@dataclass(frozen=True)
class PeerVoteDecision:
    validator_public_key: str
    verdict: str
    breaches: list[str]
    evaluated_at: datetime
    normalized_metrics: dict[str, Any]


@dataclass(frozen=True)
class ValidatorIdentity:
    validator_public_key: str
    validator_verify_key_bytes: bytes
    keys_path: Path


@dataclass(frozen=True)
class VoteArtifacts:
    canonical_payload: dict[str, Any]
    signed_payload: dict[str, Any]
    memo: Memo
    memo_hex: str


@dataclass(frozen=True)
class FeePayerContext:
    wallet: Wallet
    source: str


@dataclass(frozen=True)
class ServerMetadata:
    network_id: Optional[int]
    validated_ledger_sequence: Optional[int]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def encode_memo_field(value: str) -> str:
    return value.encode("utf-8").hex().upper()


def normalize_percentage(name: str, value: Any) -> float:
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc

    if normalized > 1:
        normalized /= 100.0

    if normalized < 0 or normalized > 1:
        raise ValueError(f"{name} must normalize into the range 0..1")

    return round(normalized, 6)


def parse_utc_timestamp(name: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty ISO 8601 string")

    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid ISO 8601 timestamp") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def load_voting_config(config_path: Path) -> VotingConfig:
    data = json.loads(config_path.read_text())
    unl_voting = data.get("unl_voting")
    if not unl_voting:
        raise ValueError("config.json is missing the unl_voting section")

    return VotingConfig(
        uptime_min_pct=normalize_percentage("uptime_min_pct", unl_voting["uptime_min_pct"]),
        latency_max_ms=int(unl_voting["latency_max_ms"]),
        consensus_min_pct=normalize_percentage("consensus_min_pct", unl_voting["consensus_min_pct"]),
        last_seen_max_age_seconds=int(unl_voting["last_seen_max_age_seconds"]),
        xrpl_rpc_url=str(unl_voting["xrpl_rpc_url"]),
        validator_keys_path=Path(unl_voting["validator_keys_path"]),
        fee_payer_seed_env=str(unl_voting.get("fee_payer_seed_env", "XRPL_FEE_PAYER_SEED")),
        dry_run_default=bool(unl_voting.get("dry_run_default", True)),
    )


def normalize_peer_record(raw_record: dict[str, Any]) -> PeerScoreRecord:
    collected_at = raw_record.get("collected_at")

    return PeerScoreRecord(
        validator_public_key=str(raw_record["validator_public_key"]).strip(),
        uptime_pct=normalize_percentage("uptime_pct", raw_record["uptime_pct"]),
        scoring_latency_ms=int(raw_record["scoring_latency_ms"]),
        consensus_participation_pct=normalize_percentage(
            "consensus_participation_pct", raw_record["consensus_participation_pct"]
        ),
        last_seen_utc=parse_utc_timestamp("last_seen_utc", raw_record["last_seen_utc"]),
        collected_at=parse_utc_timestamp("collected_at", collected_at) if collected_at else None,
    )


def load_peer_records(input_path: Path) -> tuple[list[PeerScoreRecord], list[str]]:
    raw_text = input_path.read_text().strip()
    if not raw_text:
        return [], [f"{input_path} is empty"]

    records: list[PeerScoreRecord] = []
    warnings: list[str] = []

    if raw_text.lstrip().startswith("["):
        parsed = json.loads(raw_text)
        if not isinstance(parsed, list):
            raise ValueError("JSON input must contain an array of peer records")
        raw_records = parsed
    else:
        raw_records = []
        for line_number, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw_records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                warnings.append(f"Skipped line {line_number}: invalid JSON ({exc.msg})")

    for index, raw_record in enumerate(raw_records, start=1):
        if not isinstance(raw_record, dict):
            warnings.append(f"Skipped record {index}: expected an object")
            continue
        try:
            normalized = normalize_peer_record(raw_record)
            if not normalized.validator_public_key:
                raise ValueError("validator_public_key cannot be empty")
            records.append(normalized)
        except (KeyError, TypeError, ValueError) as exc:
            warnings.append(f"Skipped record {index}: {exc}")

    return records, warnings


def evaluate_peer(
    record: PeerScoreRecord, config: VotingConfig, *, now: Optional[datetime] = None
) -> PeerVoteDecision:
    now = now or utc_now()
    age_seconds = max(0, int((now - record.last_seen_utc).total_seconds()))
    breaches: list[str] = []

    if record.uptime_pct < config.uptime_min_pct:
        breaches.append("uptime_below_min")
    if record.scoring_latency_ms > config.latency_max_ms:
        breaches.append("latency_above_max")
    if record.consensus_participation_pct < config.consensus_min_pct:
        breaches.append("consensus_below_min")
    if age_seconds > config.last_seen_max_age_seconds:
        breaches.append("last_seen_stale")

    return PeerVoteDecision(
        validator_public_key=record.validator_public_key,
        verdict="flag" if breaches else "endorse",
        breaches=breaches,
        evaluated_at=now,
        normalized_metrics={
            "validator_public_key": record.validator_public_key,
            "uptime_pct": record.uptime_pct,
            "scoring_latency_ms": record.scoring_latency_ms,
            "consensus_participation_pct": record.consensus_participation_pct,
            "last_seen_utc": format_utc(record.last_seen_utc),
            "last_seen_age_seconds": age_seconds,
            "collected_at": format_utc(record.collected_at) if record.collected_at else None,
        },
    )


def load_validator_identity(keys_path: Path) -> ValidatorIdentity:
    key_data = json.loads(keys_path.read_text())
    validator_public_key = str(key_data["public_key"])
    decoded_public_key = addresscodec.decode_node_public_key(validator_public_key)
    if len(decoded_public_key) == 33 and decoded_public_key[0] == 0xED:
        decoded_public_key = decoded_public_key[1:]
    if len(decoded_public_key) != 32:
        raise ValueError("Validator public key is not a valid Ed25519 node public key")

    return ValidatorIdentity(
        validator_public_key=validator_public_key,
        validator_verify_key_bytes=decoded_public_key,
        keys_path=keys_path,
    )


def build_metrics_digest(decision: PeerVoteDecision) -> str:
    metrics_json = json.dumps(decision.normalized_metrics, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(metrics_json.encode("utf-8")).hexdigest()


def build_vote_artifacts(decision: PeerVoteDecision, identity: ValidatorIdentity) -> VoteArtifacts:
    canonical_payload = {
        "schema": DEFAULT_MEMO_SCHEMA,
        "peer_validator_public_key": decision.validator_public_key,
        "verdict": decision.verdict,
        "evaluated_at": format_utc(decision.evaluated_at),
        "breaches": decision.breaches,
        "voter_validator_public_key": identity.validator_public_key,
        "metrics_digest_sha256": build_metrics_digest(decision),
    }

    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    validator_signature = sign_with_validator_key(canonical_json, identity)
    signed_payload = dict(canonical_payload, validator_signature=validator_signature)
    signed_payload_json = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))

    return VoteArtifacts(
        canonical_payload=canonical_payload,
        signed_payload=signed_payload,
        memo=Memo(
            memo_data=encode_memo_field(signed_payload_json),
            memo_format=encode_memo_field(DEFAULT_MEMO_FORMAT),
            memo_type=encode_memo_field(DEFAULT_MEMO_SCHEMA),
        ),
        memo_hex=encode_memo_field(signed_payload_json),
    )


def sign_with_validator_key(message: str, identity: ValidatorIdentity) -> str:
    signature_hex = invoke_validator_keys_signer(message, identity.keys_path)
    verify_validator_signature(message, signature_hex, identity)
    return signature_hex


def verify_validator_signature(message: str, signature_hex: str, identity: ValidatorIdentity) -> None:
    verify_key = nacl.signing.VerifyKey(identity.validator_verify_key_bytes)
    try:
        verify_key.verify(message.encode("utf-8"), bytes.fromhex(signature_hex))
    except (ValueError, nacl.exceptions.BadSignatureError) as exc:
        raise ValueError("validator-keys produced an invalid signature") from exc


def invoke_validator_keys_signer(message: str, keys_path: Path) -> str:
    validator_keys_bin = shutil.which("validator-keys")
    if validator_keys_bin:
        result = subprocess.run(
            [validator_keys_bin, "--keyfile", str(keys_path), "sign", message],
            capture_output=True,
            text=True,
            check=True,
        )
        return extract_signature(result.stdout)

    docker_bin = shutil.which("docker")
    if not docker_bin:
        raise RuntimeError("Neither validator-keys nor docker is available to sign validator messages")

    container_name = os.getenv("VALIDATOR_KEYS_DOCKER_CONTAINER", "postfiatd")
    temp_keyfile = f"/tmp/unl-voting-validator-keys-{os.getpid()}.json"

    try:
        subprocess.run(
            [docker_bin, "cp", str(keys_path), f"{container_name}:{temp_keyfile}"],
            capture_output=True,
            text=True,
            check=True,
        )
        result = subprocess.run(
            [
                docker_bin,
                "exec",
                container_name,
                "validator-keys",
                "--keyfile",
                temp_keyfile,
                "sign",
                message,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return extract_signature(result.stdout)
    finally:
        subprocess.run(
            [docker_bin, "exec", container_name, "rm", "-f", temp_keyfile],
            capture_output=True,
            text=True,
            check=False,
        )


def extract_signature(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("validator-keys did not return a signature")
    signature_hex = lines[-1].upper()
    if any(char not in "0123456789ABCDEF" for char in signature_hex):
        raise ValueError("validator-keys returned a non-hex signature")
    return signature_hex


def fetch_server_metadata(client: JsonRpcClient) -> ServerMetadata:
    try:
        response = client.request(ServerInfo())
        info = response.result.get("info", {})
    except Exception:
        return ServerMetadata(network_id=None, validated_ledger_sequence=None)

    validated_ledger = info.get("validated_ledger", {})
    network_id = info.get("network_id")
    if network_id is not None:
        network_id = int(network_id)

    ledger_sequence = validated_ledger.get("seq")
    if ledger_sequence is not None:
        ledger_sequence = int(ledger_sequence)

    return ServerMetadata(network_id=network_id, validated_ledger_sequence=ledger_sequence)


def fetch_account_sequence(client: JsonRpcClient, address: str) -> tuple[int, str]:
    try:
        response = client.request(AccountInfo(account=address, ledger_index="current"))
        sequence = int(response.result["account_data"]["Sequence"])
        return sequence, "account_info"
    except Exception:
        return 0, "fallback_zero"


def resolve_fee_payer_wallet(config: VotingConfig, *, allow_ephemeral: bool) -> FeePayerContext:
    configured_seed = os.getenv(config.fee_payer_seed_env)
    if configured_seed:
        return FeePayerContext(
            wallet=Wallet.from_seed(configured_seed, algorithm=CryptoAlgorithm.ED25519),
            source=f"env:{config.fee_payer_seed_env}",
        )

    if not allow_ephemeral:
        raise ValueError(
            f"{config.fee_payer_seed_env} is required for --submit because a funded fee-payer wallet is needed"
        )

    return FeePayerContext(
        wallet=Wallet.create(algorithm=CryptoAlgorithm.ED25519),
        source="generated_ephemeral_dry_run_wallet",
    )


def build_accountset_transaction(
    wallet: Wallet,
    memo: Memo,
    metadata: ServerMetadata,
    *,
    sequence: int,
) -> AccountSet:
    accountset_kwargs: dict[str, Any] = {
        "account": wallet.address,
        "fee": DEFAULT_FEE_DROPS,
        "sequence": sequence,
        "memos": [memo],
    }

    if metadata.validated_ledger_sequence is not None:
        accountset_kwargs["last_ledger_sequence"] = metadata.validated_ledger_sequence + DEFAULT_LEDGER_BUFFER
    if metadata.network_id is not None and metadata.network_id > 1024:
        accountset_kwargs["network_id"] = metadata.network_id

    return AccountSet(**accountset_kwargs)


def build_dry_run_transaction(
    client: JsonRpcClient,
    wallet_context: FeePayerContext,
    memo: Memo,
) -> tuple[AccountSet, ServerMetadata, str]:
    metadata = fetch_server_metadata(client)
    sequence, sequence_source = fetch_account_sequence(client, wallet_context.wallet.address)
    accountset = build_accountset_transaction(wallet_context.wallet, memo, metadata, sequence=sequence)
    signed_accountset = sign(accountset, wallet_context.wallet)
    return signed_accountset, metadata, sequence_source


def submit_vote_transaction(
    client: JsonRpcClient,
    wallet_context: FeePayerContext,
    memo: Memo,
) -> dict[str, Any]:
    metadata = fetch_server_metadata(client)
    accountset_kwargs: dict[str, Any] = {
        "account": wallet_context.wallet.address,
        "memos": [memo],
    }
    if metadata.network_id is not None and metadata.network_id > 1024:
        accountset_kwargs["network_id"] = metadata.network_id
    accountset = AccountSet(**accountset_kwargs)
    response = submit_and_wait(accountset, client, wallet_context.wallet, check_fee=False)
    result = response.result
    return {
        "network_id": metadata.network_id,
        "transaction_hash": result.get("hash"),
        "engine_result": result.get("engine_result"),
        "result": result,
    }


def render_output(
    record: PeerScoreRecord,
    decision: PeerVoteDecision,
    vote_artifacts: VoteArtifacts,
    wallet_context: FeePayerContext,
    *,
    dry_run: bool,
    signed_payment: Optional[AccountSet] = None,
    metadata: Optional[ServerMetadata] = None,
    sequence_source: Optional[str] = None,
    submit_result: Optional[dict[str, Any]] = None,
) -> None:
    print("=" * 72)
    print(f"Peer Vote: {record.validator_public_key}")
    print("=" * 72)
    print("[INGEST] normalized metrics")
    print(json.dumps(decision.normalized_metrics, indent=2))
    print(f"[EVALUATE] verdict={decision.verdict} breaches={decision.breaches or ['none']}")
    print("[MEMO] signed payload")
    print(json.dumps(vote_artifacts.signed_payload, indent=2))
    print(f"[MEMO] memo_data_hex={vote_artifacts.memo_hex}")
    print(f"[FEE_PAYER] source={wallet_context.source} address={wallet_context.wallet.address}")

    if dry_run and signed_payment is not None:
        print(
            "[DRY_RUN] signed accountset summary "
            f"(network_id={metadata.network_id if metadata else None}, sequence_source={sequence_source})"
        )
        print(json.dumps(signed_payment.to_dict(), indent=2))
        print(f"[DRY_RUN] signed_tx_blob={signed_payment.blob()}")
        print(f"[DRY_RUN] signed_tx_hash={signed_payment.get_hash()}")
    elif submit_result is not None:
        print("[SUBMIT] result")
        print(json.dumps(submit_result["result"], indent=2))
        print(f"[SUBMIT] transaction_hash={submit_result['transaction_hash']}")

    print()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build XRPL UNL health vote transactions")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--peer", help="Filter to a single peer validator public key")
    parser.add_argument("--submit", action="store_true", help="Submit transactions to XRPL instead of dry-run")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", help="Path to peer score JSON or JSONL file")
    input_group.add_argument("--simulate", action="store_true", help="Use bundled sample peer score data")

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    config = load_voting_config(Path(args.config))
    input_path = DEFAULT_SAMPLE_PATH if args.simulate else Path(args.input)
    dry_run = not args.submit

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    records, warnings = load_peer_records(input_path)
    for warning in warnings:
        print(f"[WARN] {warning}")

    if args.peer:
        records = [record for record in records if record.validator_public_key == args.peer]

    if not records:
        print("No valid peer records were found for voting", file=sys.stderr)
        return 1

    identity = load_validator_identity(config.validator_keys_path)
    wallet_context = resolve_fee_payer_wallet(config, allow_ephemeral=dry_run)
    client = JsonRpcClient(config.xrpl_rpc_url)

    for record in records:
        decision = evaluate_peer(record, config)
        vote_artifacts = build_vote_artifacts(decision, identity)

        if dry_run:
            signed_payment, metadata, sequence_source = build_dry_run_transaction(
                client, wallet_context, vote_artifacts.memo
            )
            render_output(
                record,
                decision,
                vote_artifacts,
                wallet_context,
                dry_run=True,
                signed_payment=signed_payment,
                metadata=metadata,
                sequence_source=sequence_source,
            )
        else:
            submit_result = submit_vote_transaction(client, wallet_context, vote_artifacts.memo)
            render_output(
                record,
                decision,
                vote_artifacts,
                wallet_context,
                dry_run=False,
                submit_result=submit_result,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
