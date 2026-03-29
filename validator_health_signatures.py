#!/usr/bin/env python3
"""
Validator health signature aggregation, broadcast, and receiver module for
PostFiat validators.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import nacl.exceptions
import nacl.signing
from xrpl.clients import JsonRpcClient
from xrpl.core import addresscodec
from xrpl.models.requests import AccountTx
from xrpl.models.transactions import Memo

from unl_governance_enforcer import DEFAULT_CONFIG_PATH, load_enforcement_config, load_health_report
from unl_voting import (
    DEFAULT_MEMO_FORMAT,
    FeePayerContext,
    ValidatorIdentity,
    build_dry_run_transaction,
    encode_memo_field,
    format_utc,
    load_validator_identity,
    load_voting_config,
    parse_utc_timestamp,
    resolve_fee_payer_wallet,
    sign_with_validator_key,
    submit_vote_transaction,
    utc_now,
)

DEFAULT_MEMO_SCHEMA = "postfiat.validator_health_signature.v1"
DEFAULT_RECENT_ACTION_LIMIT = 10
DEFAULT_FETCH_LIMIT = 10
DEFAULT_DOCKER_CONTAINER = "postfiatd"
DEMO_DIR = Path(__file__).parent / "demo"
DEFAULT_DEMO_REPORT_PATH = DEMO_DIR / "enforcement-demo-health-report.json"
DEFAULT_DEMO_ALERT_LOG_PATH = DEMO_DIR / "enforcement-alerts.jsonl"
DEFAULT_DEMO_RIPPLED_CFG_PATH = DEMO_DIR / "enforcement-demo-rippled.cfg"


@dataclass(frozen=True)
class ValidatorsSource:
    source_path: str
    source_kind: str
    text: str


@dataclass(frozen=True)
class HealthSignatureArtifacts:
    canonical_payload: dict[str, Any]
    signed_payload: dict[str, Any]
    memo: Memo
    memo_hex: str


@dataclass(frozen=True)
class HealthSignatureRecord:
    tx_hash: str
    account: str
    ledger_index: Optional[int]
    validated: Optional[bool]
    payload: dict[str, Any]
    source: str
    signing_account_matches_claim: bool
    validator_signature_valid: bool
    validation_errors: tuple[str, ...]


def decode_memo_field(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty hex string")

    try:
        decoded = bytes.fromhex(value.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hexadecimal") from exc

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must decode as UTF-8") from exc


def validator_public_key_to_verify_bytes(validator_public_key: str) -> bytes:
    decoded = addresscodec.decode_node_public_key(validator_public_key)
    if len(decoded) == 33 and decoded[0] == 0xED:
        decoded = decoded[1:]
    if len(decoded) != 32:
        raise ValueError("validator public key is not a valid Ed25519 node public key")
    return decoded


def signed_payload_to_canonical_payload(signed_payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(signed_payload, dict):
        raise ValueError("health signature payload must be a JSON object")

    canonical_payload = dict(signed_payload)
    signature = canonical_payload.pop("validator_signature", None)
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("validator_signature is required")

    schema = str(canonical_payload.get("schema", "")).strip()
    if schema != DEFAULT_MEMO_SCHEMA:
        raise ValueError(f"unsupported memo schema '{schema}'")

    node_wallet = str(canonical_payload.get("node_wallet") or canonical_payload.get("node_wallet_address") or "").strip()
    if not node_wallet:
        raise ValueError("node_wallet is required")
    node_validator = str(canonical_payload.get("node_validator") or canonical_payload.get("node_validator_public_key") or "").strip()
    if not node_validator:
        raise ValueError("node_validator is required")

    return canonical_payload


def verify_health_signature_payload(signed_payload: dict[str, Any]) -> None:
    canonical_payload = signed_payload_to_canonical_payload(signed_payload)
    signature_hex = str(signed_payload["validator_signature"]).strip()
    verify_key = nacl.signing.VerifyKey(
        validator_public_key_to_verify_bytes(str(canonical_payload.get("node_validator") or canonical_payload.get("node_validator_public_key")).strip())
    )
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))

    try:
        verify_key.verify(canonical_json.encode("utf-8"), bytes.fromhex(signature_hex))
    except (ValueError, nacl.exceptions.BadSignatureError) as exc:
        raise ValueError("validator signature verification failed") from exc


def build_health_signature_artifacts(payload: dict[str, Any], identity: ValidatorIdentity) -> HealthSignatureArtifacts:
    canonical_payload = dict(payload)
    canonical_payload["schema"] = DEFAULT_MEMO_SCHEMA
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    validator_signature = sign_with_validator_key(canonical_json, identity)
    signed_payload = dict(canonical_payload, validator_signature=validator_signature)
    signed_payload_json = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))

    return HealthSignatureArtifacts(
        canonical_payload=canonical_payload,
        signed_payload=signed_payload,
        memo=Memo(
            memo_data=encode_memo_field(signed_payload_json),
            memo_format=encode_memo_field(DEFAULT_MEMO_FORMAT),
            memo_type=encode_memo_field(DEFAULT_MEMO_SCHEMA),
        ),
        memo_hex=encode_memo_field(signed_payload_json),
    )
def extract_section_entries(text: str, section_name: str) -> list[str]:
    target = section_name.strip().lower()
    current_section: Optional[str] = None
    values: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1].strip().lower()
            continue
        if current_section == target:
            values.append(stripped)

    return values


def parse_validators_file_reference(config_text: str) -> Optional[str]:
    entries = extract_section_entries(config_text, "validators_file")
    if not entries:
        return None
    return entries[0].split()[0].strip()


def inspect_container_conf_path(container_name: str) -> Optional[str]:
    result = subprocess.run(["docker", "inspect", container_name], capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return None

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    if not payload:
        return None

    container = payload[0]
    candidate_lists = [container.get("Args") or [], container.get("Config", {}).get("Cmd") or []]
    for candidates in candidate_lists:
        for index, value in enumerate(candidates):
            if value == "--conf" and index + 1 < len(candidates):
                return str(candidates[index + 1])

    return None


def read_text_from_container(container_name: str, container_path: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container_name, "cat", container_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise FileNotFoundError(f"unable to read {container_name}:{container_path} ({stderr})")
    return result.stdout


def resolve_rippled_cfg_path(config_path: Path, override_path: Optional[Path]) -> Path:
    if override_path is not None:
        if not override_path.exists():
            raise FileNotFoundError(f"rippled/postfiatd config not found: {override_path}")
        return override_path

    candidates: list[Path] = []
    try:
        candidates.append(load_enforcement_config(config_path).rippled_cfg_path)
    except Exception:
        pass
    candidates.extend([Path("/opt/postfiatd/postfiatd.cfg"), Path("/home/postfiat/.config/rippled/rippled.cfg")])

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.exists():
            return candidate

    raise FileNotFoundError("unable to locate a readable rippled/postfiatd config file")


def resolve_validators_source(
    cfg_path: Optional[Path],
    *,
    validators_file_override: Optional[Path],
    docker_container: str,
) -> ValidatorsSource:
    if validators_file_override is not None:
        if not validators_file_override.exists():
            raise FileNotFoundError(f"validators file not found: {validators_file_override}")
        return ValidatorsSource(
            source_path=str(validators_file_override),
            source_kind="host_file_override",
            text=validators_file_override.read_text(),
        )

    if cfg_path is None or not cfg_path.exists():
        raise FileNotFoundError("unable to resolve a config file for local UNL state")

    config_text = cfg_path.read_text()
    validators_file_reference = parse_validators_file_reference(config_text)
    if not validators_file_reference:
        return ValidatorsSource(source_path=str(cfg_path), source_kind="host_config", text=config_text)

    validators_host_path = Path(validators_file_reference)
    if not validators_host_path.is_absolute():
        validators_host_path = cfg_path.parent / validators_file_reference
    if validators_host_path.exists():
        return ValidatorsSource(
            source_path=str(validators_host_path),
            source_kind="host_file",
            text=validators_host_path.read_text(),
        )

    container_conf_path = inspect_container_conf_path(docker_container)
    if container_conf_path:
        if validators_file_reference.startswith("/"):
            container_validators_path = validators_file_reference
        else:
            container_validators_path = str(PurePosixPath(container_conf_path).parent / validators_file_reference)
        return ValidatorsSource(
            source_path=f"{docker_container}:{container_validators_path}",
            source_kind="docker_file",
            text=read_text_from_container(docker_container, container_validators_path),
        )

    raise FileNotFoundError(
        "validators_file is configured but was not readable on the host and no docker fallback was available"
    )


def build_local_unl_state(source: ValidatorsSource) -> dict[str, Any]:
    validators: list[str] = []
    validator_list_sites: list[str] = []
    validator_list_keys: list[str] = []
    validator_list_threshold: Optional[str] = None
    current_section: Optional[str] = None

    for line in source.text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1].strip().lower()
            continue

        if current_section == "validators":
            validators.append(stripped.split()[0])
        elif current_section == "validator_list_sites":
            validator_list_sites.append(stripped)
        elif current_section == "validator_list_keys":
            validator_list_keys.append(stripped.split()[0])
        elif current_section == "validator_list_threshold" and validator_list_threshold is None:
            validator_list_threshold = stripped.split()[0]

    canonical_state = {
        "validators": sorted(set(validators)),
        "validator_list_sites": sorted(set(validator_list_sites)),
        "validator_list_keys": sorted(set(validator_list_keys)),
        "validator_list_threshold": validator_list_threshold,
    }
    canonical_json = json.dumps(canonical_state, sort_keys=True, separators=(",", ":"))

    return {
        "source_path": source.source_path,
        "validators": len(canonical_state["validators"]),
        "sites": len(canonical_state["validator_list_sites"]),
        "keys": len(canonical_state["validator_list_keys"]),
        "threshold": validator_list_threshold,
        "hash": hashlib.sha256(canonical_json.encode("utf-8")).hexdigest(),
    }


def load_local_unl_state(
    *,
    config_path: Path,
    rippled_cfg_path: Optional[Path],
    validators_file_path: Optional[Path],
    docker_container: str,
) -> dict[str, Any]:
    resolved_cfg_path: Optional[Path] = None
    if validators_file_path is None:
        resolved_cfg_path = resolve_rippled_cfg_path(config_path, rippled_cfg_path)

    validators_source = resolve_validators_source(
        resolved_cfg_path,
        validators_file_override=validators_file_path,
        docker_container=docker_container,
    )
    return build_local_unl_state(validators_source)
def normalize_governance_action(raw_entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    event = str(raw_entry.get("event", "")).strip()
    if event == "UNL_JAIL_ENFORCED":
        action = "jail"
    elif event == "UNL_WARN_ALERT":
        action = "warn"
    else:
        return None

    timestamp = parse_utc_timestamp("timestamp", raw_entry.get("timestamp"))
    return {
        "ts": format_utc(timestamp),
        "action": action,
        "target": str(raw_entry.get("target_validator_address", "")).strip(),
    }


def load_recent_governance_actions(
    alert_log_path: Optional[Path],
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    if limit < 0:
        raise ValueError("recent actions limit must be zero or greater")
    if alert_log_path is None or not alert_log_path.exists():
        return [], []

    normalized_entries: list[tuple[str, dict[str, Any]]] = []
    warnings: list[str] = []

    for line_number, line in enumerate(alert_log_path.read_text().splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            raw_entry = json.loads(stripped)
        except json.JSONDecodeError as exc:
            warnings.append(f"Skipped alert log line {line_number}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(raw_entry, dict):
            warnings.append(f"Skipped alert log line {line_number}: expected an object")
            continue
        try:
            normalized = normalize_governance_action(raw_entry)
        except ValueError as exc:
            warnings.append(f"Skipped alert log line {line_number}: {exc}")
            continue
        if normalized is not None:
            normalized_entries.append((normalized["ts"], normalized))

    normalized_entries.sort(key=lambda item: item[0])
    if limit == 0:
        return [], warnings
    return [entry for _timestamp, entry in normalized_entries[-limit:]], warnings


def map_tally_status(tally: Any) -> str:
    if tally.recommended_action == "jail":
        return "jail"
    if tally.recommended_action == "warn":
        return "flag"
    return "endorse"


def compute_tally_score(tally: Any) -> float:
    if tally.total_votes <= 0:
        return 0.0
    return round((tally.endorse_votes - tally.flag_votes) / tally.total_votes, 6)


def aggregate_peer_scores(report: Any) -> list[dict[str, Any]]:
    peer_scores: list[dict[str, Any]] = []
    for tally in sorted(report.tallies, key=lambda item: item.target_validator_address):
        peer_scores.append(
            {
                "wallet": tally.target_validator_address,
                "score": compute_tally_score(tally),
                "status": map_tally_status(tally),
            }
        )
    return peer_scores


def build_health_signature_payload(
    report: Any,
    *,
    node_wallet_address: str,
    node_validator_public_key: str,
    governance_actions: list[dict[str, Any]],
    local_unl_state: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": DEFAULT_MEMO_SCHEMA,
        "node_wallet": node_wallet_address,
        "node_validator": node_validator_public_key,
        "ts": format_utc(utc_now()),
        "peer_scores": aggregate_peer_scores(report),
        "actions": governance_actions,
        "local_unl": {
            "hash": local_unl_state["hash"],
            "validators": local_unl_state["validators"],
            "sites": local_unl_state["sites"],
            "keys": local_unl_state["keys"],
            "threshold": local_unl_state["threshold"],
        },
    }


def aggregate_health_signature_payload(
    report_path: Path,
    *,
    node_wallet_address: str,
    node_validator_public_key: str,
    config_path: Path,
    alert_log_path: Optional[Path],
    recent_actions_limit: int,
    rippled_cfg_path: Optional[Path],
    validators_file_path: Optional[Path],
    docker_container: str,
) -> tuple[dict[str, Any], list[str]]:
    if not report_path.exists():
        raise FileNotFoundError(f"health report not found: {report_path}")

    report = load_health_report(report_path)
    governance_actions, warnings = load_recent_governance_actions(alert_log_path, limit=recent_actions_limit)
    local_unl_state = load_local_unl_state(
        config_path=config_path,
        rippled_cfg_path=rippled_cfg_path,
        validators_file_path=validators_file_path,
        docker_container=docker_container,
    )
    payload = build_health_signature_payload(
        report,
        node_wallet_address=node_wallet_address,
        node_validator_public_key=node_validator_public_key,
        governance_actions=governance_actions,
        local_unl_state=local_unl_state,
    )
    return payload, warnings


def parse_health_signature_memo_payload(memo: dict[str, Any]) -> Optional[dict[str, Any]]:
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


def extract_health_signature_records(raw_entry: dict[str, Any]) -> list[HealthSignatureRecord]:
    if isinstance(raw_entry.get("tx"), dict):
        tx_container = raw_entry["tx"]
    elif isinstance(raw_entry.get("tx_json"), dict):
        tx_container = raw_entry["tx_json"]
    else:
        tx_container = raw_entry
    if not isinstance(tx_container, dict):
        raise ValueError("transaction entry must be an object")

    account = str(tx_container.get("Account", "")).strip()
    tx_hash = str(tx_container.get("hash") or raw_entry.get("hash") or "").strip() or "unknown"
    ledger_index_raw = raw_entry.get("ledger_index", tx_container.get("ledger_index"))
    try:
        ledger_index = int(ledger_index_raw) if ledger_index_raw is not None else None
    except (TypeError, ValueError):
        ledger_index = None
    validated = raw_entry.get("validated")

    memos = tx_container.get("Memos") or tx_container.get("memos") or []
    records: list[HealthSignatureRecord] = []
    for memo_index, memo_wrapper in enumerate(memos, start=1):
        memo = memo_wrapper
        while isinstance(memo, dict) and isinstance(memo.get("Memo"), dict):
            memo = memo["Memo"]
        if not isinstance(memo, dict):
            continue
        try:
            payload = parse_health_signature_memo_payload(memo)
            if payload is None:
                continue
            claimed_wallet = str(payload.get("node_wallet") or payload.get("node_wallet_address") or "").strip()
            account_matches_claim = bool(claimed_wallet) and claimed_wallet == account
            validation_errors: list[str] = []
            if not account_matches_claim:
                validation_errors.append("transaction Account does not match payload node_wallet_address")

            signature_valid = True
            try:
                verify_health_signature_payload(payload)
            except ValueError as exc:
                signature_valid = False
                validation_errors.append(str(exc))

            records.append(
                HealthSignatureRecord(
                    tx_hash=tx_hash,
                    account=account,
                    ledger_index=ledger_index,
                    validated=bool(validated) if validated is not None else None,
                    payload=payload,
                    source=f"memo[{memo_index}]",
                    signing_account_matches_claim=account_matches_claim,
                    validator_signature_valid=signature_valid,
                    validation_errors=tuple(validation_errors),
                )
            )
        except ValueError as exc:
            records.append(
                HealthSignatureRecord(
                    tx_hash=tx_hash,
                    account=account,
                    ledger_index=ledger_index,
                    validated=bool(validated) if validated is not None else None,
                    payload={},
                    source=f"memo[{memo_index}]",
                    signing_account_matches_claim=False,
                    validator_signature_valid=False,
                    validation_errors=(str(exc),),
                )
            )

    return records
def fetch_health_signature_records(
    client: JsonRpcClient,
    *,
    account: str,
    limit: int,
    tx_hash: Optional[str],
) -> list[HealthSignatureRecord]:
    if limit <= 0:
        raise ValueError("fetch limit must be greater than zero")

    records: list[HealthSignatureRecord] = []
    marker: Any = None
    page_limit = min(max(limit * 4, 20), 200)

    while len(records) < limit:
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
        for raw_entry in response.result.get("transactions", []):
            if isinstance(raw_entry, dict):
                records.extend(extract_health_signature_records(raw_entry))
        marker = response.result.get("marker")
        if marker is None:
            break

    filtered = sorted(
        records,
        key=lambda record: ((record.ledger_index or 0), record.tx_hash, record.source),
        reverse=True,
    )
    if tx_hash:
        filtered = [record for record in filtered if record.tx_hash == tx_hash]
    return filtered[:limit]


def health_signature_record_to_dict(record: HealthSignatureRecord) -> dict[str, Any]:
    return {
        "tx_hash": record.tx_hash,
        "account": record.account,
        "ledger_index": record.ledger_index,
        "validated": record.validated,
        "source": record.source,
        "signing_account_matches_claim": record.signing_account_matches_claim,
        "validator_signature_valid": record.validator_signature_valid,
        "validation_errors": list(record.validation_errors),
        "payload": record.payload,
    }


def resolve_input_paths(args: argparse.Namespace, config_path: Path) -> tuple[Path, Optional[Path], Optional[Path], Optional[Path]]:
    if args.simulate:
        return (
            DEFAULT_DEMO_REPORT_PATH,
            DEFAULT_DEMO_ALERT_LOG_PATH,
            DEFAULT_DEMO_RIPPLED_CFG_PATH,
            None,
        )

    if not args.report:
        raise ValueError("--report is required unless --simulate is used")

    report_path = Path(args.report)
    if not report_path.exists():
        raise FileNotFoundError(f"health report not found: {report_path}")

    alert_log_path = Path(args.alert_log) if args.alert_log else None
    if alert_log_path is None:
        try:
            alert_log_path = load_enforcement_config(config_path).alert_log_path
        except Exception:
            alert_log_path = None

    rippled_cfg_path = Path(args.rippled_cfg) if args.rippled_cfg else None
    validators_file_path = Path(args.validators_file) if args.validators_file else None
    return report_path, alert_log_path, rippled_cfg_path, validators_file_path


def render_aggregation(
    payload: dict[str, Any],
    *,
    report_path: Path,
    alert_log_path: Optional[Path],
    warnings: list[str],
) -> None:
    print("=" * 72)
    print("Validator Health Signature Aggregation")
    print("=" * 72)
    print(
        "[AGGREGATE] "
        f"report_path={report_path} "
        f"peer_scores={len(payload['peer_scores'])} "
        f"recent_actions={len(payload['actions'])}"
    )
    print(
        "[AGGREGATE] "
        f"alert_log_path={alert_log_path or 'n/a'} "
        f"unl_hash={payload['local_unl']['hash']} "
        f"validators={payload['local_unl']['validators']} "
        f"sites={payload['local_unl']['sites']}"
    )
    print(
        "[AGGREGATE] "
        f"node_wallet={payload['node_wallet']} "
        f"node_validator={payload['node_validator']}"
    )
    for warning in warnings:
        print(f"[WARN] {warning}")
    print("[PAYLOAD] structured JSON payload")
    print(json.dumps(payload, indent=2))
    print()


def render_broadcast(
    payload: dict[str, Any],
    artifacts: HealthSignatureArtifacts,
    wallet_context: FeePayerContext,
    *,
    report_path: Path,
    alert_log_path: Optional[Path],
    warnings: list[str],
    dry_run: bool,
    signed_transaction: Optional[Any] = None,
    sequence_source: Optional[str] = None,
    submit_result: Optional[dict[str, Any]] = None,
) -> None:
    print("=" * 72)
    print("Validator Health Signature Broadcast")
    print("=" * 72)
    print(
        "[AGGREGATE] "
        f"report_path={report_path} "
        f"peer_scores={len(payload['peer_scores'])} "
        f"recent_actions={len(payload['actions'])}"
    )
    print(
        "[AGGREGATE] "
        f"alert_log_path={alert_log_path or 'n/a'} "
        f"unl_hash={payload['local_unl']['hash']} "
        f"validators={payload['local_unl']['validators']} "
        f"sites={payload['local_unl']['sites']}"
    )
    for warning in warnings:
        print(f"[WARN] {warning}")
    print("[PAYLOAD] structured JSON payload")
    print(json.dumps(payload, indent=2))
    print("[MEMO] signed payload")
    print(json.dumps(artifacts.signed_payload, indent=2))
    print(f"[MEMO] memo_data_hex={artifacts.memo_hex}")
    print(f"[FEE_PAYER] source={wallet_context.source} address={wallet_context.wallet.address}")

    if dry_run and signed_transaction is not None:
        print(f"[DRY_RUN] sequence_source={sequence_source}")
        print(json.dumps(signed_transaction.to_dict(), indent=2))
        print(f"[DRY_RUN] signed_tx_hash={signed_transaction.get_hash()}")
    elif submit_result is not None:
        print("[SUBMIT] result")
        print(json.dumps(submit_result["result"], indent=2))
        print(f"[SUBMIT] transaction_hash={submit_result['transaction_hash']}")

    print()


def render_received_signatures(records: list[HealthSignatureRecord], *, accounts: list[str], tx_hash: Optional[str]) -> None:
    print("=" * 72)
    print("Validator Health Signature Receiver")
    print("=" * 72)
    print(
        "[FETCH] "
        f"accounts={','.join(accounts)} "
        f"memo_type={DEFAULT_MEMO_SCHEMA} "
        f"matches={len(records)}"
    )
    if tx_hash:
        print(f"[FETCH] tx_hash_filter={tx_hash}")

    for record in records:
        print(
            "[RECEIVE] "
            f"tx={record.tx_hash} "
            f"account={record.account or 'n/a'} "
            f"claimed_wallet={record.payload.get('node_wallet') or record.payload.get('node_wallet_address', 'n/a')} "
            f"wallet_match={'yes' if record.signing_account_matches_claim else 'no'} "
            f"signature_valid={'yes' if record.validator_signature_valid else 'no'} "
            f"generated_at={record.payload.get('ts') or record.payload.get('generated_at', 'n/a')}"
        )
        if record.validation_errors:
            print(f"[WARN] validation_errors={json.dumps(list(record.validation_errors))}")
        print(json.dumps(record.payload, indent=2))
        print()
def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate, broadcast, and receive validator health signatures over XRPL memos"
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--rpc-url", help="Override the XRPL JSON-RPC URL used for broadcast and receive")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_aggregation_inputs(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--report", help="Path to deterministic UNL health report JSON")
        subparser.add_argument("--alert-log", help="Path to governance alert JSONL")
        subparser.add_argument(
            "--recent-actions-limit",
            type=int,
            default=DEFAULT_RECENT_ACTION_LIMIT,
            help="Maximum number of recent jail/warn events to include",
        )
        subparser.add_argument("--rippled-cfg", help="Path to rippled/postfiatd config for local UNL state")
        subparser.add_argument("--validators-file", help="Path to validators.txt override")
        subparser.add_argument(
            "--docker-container",
            default=DEFAULT_DOCKER_CONTAINER,
            help="Docker container name used to resolve validators.txt when it is not on the host",
        )
        subparser.add_argument("--simulate", action="store_true", help="Use the bundled demo health data")
        subparser.add_argument("--json-out", help="Write the aggregated JSON output to this path")

    aggregate_parser = subparsers.add_parser("aggregate", help="Aggregate local health data into a JSON payload")
    add_aggregation_inputs(aggregate_parser)
    aggregate_parser.add_argument("--node-wallet-address", help="Override the claimed node wallet address")

    broadcast_parser = subparsers.add_parser("broadcast", help="Aggregate, sign, and broadcast the health signature")
    add_aggregation_inputs(broadcast_parser)
    broadcast_parser.add_argument("--node-wallet-address", help="Must match the fee-payer wallet when provided")
    broadcast_parser.add_argument("--submit", action="store_true", help="Submit the memo transaction to XRPL")

    receive_parser = subparsers.add_parser("receive", help="Fetch and validate health signature memos from XRPL")
    receive_parser.add_argument("--account", action="append", required=True, help="XRPL account to scan for memos")
    receive_parser.add_argument("--limit", type=int, default=DEFAULT_FETCH_LIMIT, help="Maximum signatures to return")
    receive_parser.add_argument("--tx-hash", help="Optional transaction hash filter")
    receive_parser.add_argument(
        "--show-invalid",
        action="store_true",
        help="Include records that failed account-match or validator-signature validation",
    )
    receive_parser.add_argument("--json-out", help="Write fetched signature records as JSON to this path")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config_path = Path(args.config)
        voting_config = load_voting_config(config_path)

        if args.command in {"aggregate", "broadcast"}:
            identity = load_validator_identity(voting_config.validator_keys_path)
            report_path, alert_log_path, rippled_cfg_path, validators_file_path = resolve_input_paths(args, config_path)

            if args.command == "broadcast":
                dry_run = not args.submit
                wallet_context = resolve_fee_payer_wallet(voting_config, allow_ephemeral=dry_run)
                if args.node_wallet_address and args.node_wallet_address.strip() != wallet_context.wallet.address:
                    raise ValueError("--node-wallet-address must match the fee-payer wallet address for broadcast")
                node_wallet_address = wallet_context.wallet.address
            else:
                if args.node_wallet_address:
                    node_wallet_address = args.node_wallet_address.strip()
                else:
                    try:
                        node_wallet_address = resolve_fee_payer_wallet(voting_config, allow_ephemeral=False).wallet.address
                    except ValueError as exc:
                        raise ValueError(
                            "--node-wallet-address is required when the configured fee-payer seed is not available"
                        ) from exc

            payload, warnings = aggregate_health_signature_payload(
                report_path,
                node_wallet_address=node_wallet_address,
                node_validator_public_key=identity.validator_public_key,
                config_path=config_path,
                alert_log_path=alert_log_path,
                recent_actions_limit=args.recent_actions_limit,
                rippled_cfg_path=rippled_cfg_path,
                validators_file_path=validators_file_path,
                docker_container=args.docker_container,
            )

            if args.command == "aggregate":
                render_aggregation(payload, report_path=report_path, alert_log_path=alert_log_path, warnings=warnings)
                if args.json_out:
                    Path(args.json_out).write_text(json.dumps(payload, indent=2))
                    print(f"[PAYLOAD] json_path={args.json_out}")
                return 0

            artifacts = build_health_signature_artifacts(payload, identity)
            client = JsonRpcClient(args.rpc_url or voting_config.xrpl_rpc_url)
            if dry_run:
                signed_transaction, _metadata, sequence_source = build_dry_run_transaction(
                    client, wallet_context, artifacts.memo
                )
                render_broadcast(
                    payload,
                    artifacts,
                    wallet_context,
                    report_path=report_path,
                    alert_log_path=alert_log_path,
                    warnings=warnings,
                    dry_run=True,
                    signed_transaction=signed_transaction,
                    sequence_source=sequence_source,
                )
                if args.json_out:
                    Path(args.json_out).write_text(json.dumps(artifacts.signed_payload, indent=2))
                    print(f"[PAYLOAD] json_path={args.json_out}")
                return 0

            submit_result = submit_vote_transaction(client, wallet_context, artifacts.memo)
            render_broadcast(
                payload,
                artifacts,
                wallet_context,
                report_path=report_path,
                alert_log_path=alert_log_path,
                warnings=warnings,
                dry_run=False,
                submit_result=submit_result,
            )
            if args.json_out:
                Path(args.json_out).write_text(json.dumps(artifacts.signed_payload, indent=2))
                print(f"[PAYLOAD] json_path={args.json_out}")
            return 0

        client = JsonRpcClient(args.rpc_url or voting_config.xrpl_rpc_url)
        fetched_records: list[HealthSignatureRecord] = []
        for account in args.account:
            fetched_records.extend(
                fetch_health_signature_records(
                    client,
                    account=account,
                    limit=args.limit,
                    tx_hash=args.tx_hash,
                )
            )

        fetched_records = sorted(
            fetched_records,
            key=lambda record: ((record.ledger_index or 0), record.tx_hash, record.source),
            reverse=True,
        )
        if not args.show_invalid:
            fetched_records = [
                record
                for record in fetched_records
                if record.signing_account_matches_claim and record.validator_signature_valid
            ]

        if not fetched_records:
            print("No matching health signature memos were found", file=sys.stderr)
            return 1

        render_received_signatures(fetched_records, accounts=args.account, tx_hash=args.tx_hash)
        if args.json_out:
            payload = [health_signature_record_to_dict(record) for record in fetched_records]
            Path(args.json_out).write_text(json.dumps(payload, indent=2))
            print(f"[FETCH] json_path={args.json_out}")
        return 0
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())