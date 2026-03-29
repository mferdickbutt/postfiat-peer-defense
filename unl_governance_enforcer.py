#!/usr/bin/env python3
"""
Autonomous governance enforcement for deterministic UNL health reports.

Consumes the JSON health report emitted by unl_vote_tally.py, maps each
validator recommendation to an operational action, and closes the loop between
vote aggregation and local node enforcement.
"""

from __future__ import annotations

import argparse
import difflib
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from unl_vote_tally import format_ratio, format_utc, parse_utc_timestamp, utc_now

DEFAULT_CONFIG_PATH = Path("/home/postfiat/peer-defense/config.json")
DEFAULT_VALIDATORS_SECTION = "validators"


@dataclass(frozen=True)
class EnforcementConfig:
    rippled_cfg_path: Path
    trusted_validators_section: str
    peer_filter_reload_command: tuple[str, ...]
    warn_cooldown_minutes: int
    alert_log_path: Path
    recheck_schedule_path: Path


@dataclass(frozen=True)
class HealthReportTally:
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
class HealthReport:
    generated_at_utc: Optional[str]
    ingested_vote_count: int
    deduped_vote_count: int
    active_validator_count: int
    tallies: tuple[HealthReportTally, ...]


@dataclass(frozen=True)
class RippledValidatorsState:
    text: str
    validator_keys: tuple[str, ...]
    section_present: bool


@dataclass(frozen=True)
class RippledValidatorsUpdate:
    updated_text: str
    before_keys: tuple[str, ...]
    after_keys: tuple[str, ...]
    section_present: bool
    changed: bool
    removed_keys: tuple[str, ...]
    added_keys: tuple[str, ...]
    diff: str


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


def load_enforcement_config(config_path: Path) -> EnforcementConfig:
    data = json.loads(config_path.read_text())
    raw = data.get("unl_enforcement")
    if not raw:
        raise ValueError("config.json is missing the unl_enforcement section")

    command = parse_reload_command(raw.get("peer_filter_reload_command"))
    cooldown_minutes = int(raw.get("warn_cooldown_minutes", 60))
    if cooldown_minutes <= 0:
        raise ValueError("warn_cooldown_minutes must be greater than zero")

    return EnforcementConfig(
        rippled_cfg_path=Path(str(raw["rippled_cfg_path"])),
        trusted_validators_section=str(raw.get("trusted_validators_section", DEFAULT_VALIDATORS_SECTION)).strip()
        or DEFAULT_VALIDATORS_SECTION,
        peer_filter_reload_command=command,
        warn_cooldown_minutes=cooldown_minutes,
        alert_log_path=Path(str(raw["alert_log_path"])),
        recheck_schedule_path=Path(str(raw["recheck_schedule_path"])),
    )


def parse_reload_command(raw_value: Any) -> tuple[str, ...]:
    if isinstance(raw_value, str):
        parsed = tuple(part for part in shlex.split(raw_value) if part)
    elif isinstance(raw_value, list):
        parsed = tuple(str(part).strip() for part in raw_value if str(part).strip())
    else:
        raise ValueError("peer_filter_reload_command must be a string or an array of command parts")

    if not parsed:
        raise ValueError("peer_filter_reload_command cannot be empty")

    return parsed


def load_health_report(report_path: Path) -> HealthReport:
    data = json.loads(report_path.read_text())
    tallies_raw = data.get("tallies")
    if not isinstance(tallies_raw, list):
        raise ValueError("health report is missing the tallies array")

    tallies: list[HealthReportTally] = []
    for index, raw_tally in enumerate(tallies_raw, start=1):
        if not isinstance(raw_tally, dict):
            raise ValueError(f"health report tally {index} must be an object")

        action = str(raw_tally["recommended_action"]).strip().lower()
        if action not in {"jail", "warn", "maintain"}:
            raise ValueError(f"health report tally {index} has unsupported action '{action}'")

        tallies.append(
            HealthReportTally(
                target_validator_address=str(raw_tally["target_validator_address"]).strip(),
                flag_votes=int(raw_tally["flag_votes"]),
                endorse_votes=int(raw_tally["endorse_votes"]),
                total_votes=int(raw_tally["total_votes"]),
                voters_participating=int(raw_tally["voters_participating"]),
                active_validator_count=int(raw_tally["active_validator_count"]),
                participation_ratio=float(raw_tally["participation_ratio"]),
                flag_ratio=float(raw_tally["flag_ratio"]),
                endorse_ratio=float(raw_tally["endorse_ratio"]),
                quorum_met=bool(raw_tally["quorum_met"]),
                recommended_action=action,
                threshold_reason=str(raw_tally["threshold_reason"]).strip(),
            )
        )

    generated_at = data.get("generated_at_utc")
    if generated_at:
        parse_utc_timestamp("generated_at_utc", generated_at)

    return HealthReport(
        generated_at_utc=str(generated_at).strip() if generated_at else None,
        ingested_vote_count=int(data.get("ingested_vote_count", len(tallies))),
        deduped_vote_count=int(data.get("deduped_vote_count", len(tallies))),
        active_validator_count=int(data.get("active_validator_count", 0)),
        tallies=tuple(tallies),
    )


def read_trusted_validators(config_text: str, section_name: str) -> RippledValidatorsState:
    lines = config_text.splitlines()
    section_index = find_section_index(lines, section_name)
    validator_keys: list[str] = []

    if section_index is None:
        return RippledValidatorsState(text=config_text, validator_keys=tuple(), section_present=False)

    section_end = find_section_end(lines, section_index)
    for line in lines[section_index + 1 : section_end]:
        validator_key = extract_validator_key(line)
        if validator_key:
            validator_keys.append(validator_key)

    return RippledValidatorsState(text=config_text, validator_keys=tuple(validator_keys), section_present=True)


def find_section_index(lines: list[str], section_name: str) -> Optional[int]:
    expected = f"[{section_name.lower()}]"
    for index, line in enumerate(lines):
        if line.strip().lower() == expected:
            return index
    return None


def find_section_end(lines: list[str], section_index: int) -> int:
    for index in range(section_index + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            return index
    return len(lines)


def extract_validator_key(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith(";"):
        return None
    return stripped.split()[0]


def update_trusted_validators(
    config_text: str,
    *,
    section_name: str,
    remove_keys: tuple[str, ...] = (),
    add_keys: tuple[str, ...] = (),
) -> RippledValidatorsUpdate:
    lines = config_text.splitlines()
    newline = detect_newline(config_text)
    section_index = find_section_index(lines, section_name)
    before_state = read_trusted_validators(config_text, section_name)
    before_keys = before_state.validator_keys
    remove_lookup = set(remove_keys)

    if section_index is None:
        updated_lines = list(lines)
        if add_keys:
            if updated_lines and updated_lines[-1].strip():
                updated_lines.append("")
            updated_lines.append(f"[{section_name}]")
            updated_lines.extend(add_keys)
        updated_text = config_text if updated_lines == lines else normalize_config_text(updated_lines, newline)
    else:
        section_end = find_section_end(lines, section_index)
        kept_lines: list[str] = []
        present_keys: list[str] = []
        for line in lines[section_index + 1 : section_end]:
            validator_key = extract_validator_key(line)
            if validator_key and validator_key in remove_lookup:
                continue
            kept_lines.append(line)
            if validator_key:
                present_keys.append(validator_key)

        appended_keys = [key for key in add_keys if key not in present_keys]
        if appended_keys:
            if kept_lines and kept_lines[-1].strip():
                kept_lines.append("")
            kept_lines.extend(appended_keys)

        updated_lines = lines[: section_index + 1] + kept_lines + lines[section_end:]
        updated_text = config_text if updated_lines == lines else normalize_config_text(updated_lines, newline)

    after_state = read_trusted_validators(updated_text, section_name)
    after_keys = after_state.validator_keys
    removed_keys = tuple(key for key in before_keys if key not in after_keys)
    added_keys_effective = tuple(key for key in after_keys if key not in before_keys)
    diff = render_config_diff(config_text, updated_text)

    return RippledValidatorsUpdate(
        updated_text=updated_text,
        before_keys=before_keys,
        after_keys=after_keys,
        section_present=section_index is not None,
        changed=config_text != updated_text,
        removed_keys=removed_keys,
        added_keys=added_keys_effective,
        diff=diff,
    )


def detect_newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def normalize_config_text(lines: list[str], newline: str) -> str:
    return newline.join(lines).rstrip() + newline


def render_config_diff(before_text: str, after_text: str) -> str:
    diff_lines = list(
        difflib.unified_diff(
            before_text.splitlines(),
            after_text.splitlines(),
            fromfile="rippled.cfg.before",
            tofile="rippled.cfg.after",
            lineterm="",
        )
    )
    return "\n".join(diff_lines)


def append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def run_command(command: tuple[str, ...]) -> CommandResult:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return CommandResult(
        exit_code=result.returncode,
        stdout=result.stdout.strip(),
        stderr=result.stderr.strip(),
    )


def shell_join(command: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def build_jail_alert_entry(tally: HealthReportTally, report_path: Path) -> dict[str, Any]:
    return {
        "timestamp": format_utc(utc_now()),
        "event": "UNL_JAIL_ENFORCED",
        "report_path": str(report_path),
        "target_validator_address": tally.target_validator_address,
        "recommended_action": tally.recommended_action,
        "flag_votes": tally.flag_votes,
        "endorse_votes": tally.endorse_votes,
        "total_votes": tally.total_votes,
        "participation_ratio": tally.participation_ratio,
        "flag_ratio": tally.flag_ratio,
        "threshold_reason": tally.threshold_reason,
    }


def build_warn_alert_entry(tally: HealthReportTally, report_path: Path) -> dict[str, Any]:
    return {
        "timestamp": format_utc(utc_now()),
        "event": "UNL_WARN_ALERT",
        "report_path": str(report_path),
        "target_validator_address": tally.target_validator_address,
        "recommended_action": tally.recommended_action,
        "flag_votes": tally.flag_votes,
        "endorse_votes": tally.endorse_votes,
        "total_votes": tally.total_votes,
        "participation_ratio": tally.participation_ratio,
        "flag_ratio": tally.flag_ratio,
        "threshold_reason": tally.threshold_reason,
    }


def build_recheck_entry(
    tally: HealthReportTally,
    report_path: Path,
    *,
    cooldown_minutes: int,
) -> dict[str, Any]:
    scheduled_at = utc_now()
    recheck_at = scheduled_at + timedelta_minutes(cooldown_minutes)
    return {
        "timestamp": format_utc(scheduled_at),
        "event": "UNL_WARN_RECHECK_SCHEDULED",
        "report_path": str(report_path),
        "target_validator_address": tally.target_validator_address,
        "recommended_action": tally.recommended_action,
        "flag_ratio": tally.flag_ratio,
        "participation_ratio": tally.participation_ratio,
        "cooldown_minutes": cooldown_minutes,
        "recheck_not_before_utc": format_utc(recheck_at),
    }


def timedelta_minutes(minutes: int):
    from datetime import timedelta

    return timedelta(minutes=minutes)


def enforce_governance(report: HealthReport, config: EnforcementConfig, report_path: Path) -> int:
    print("=" * 72)
    print("UNL Governance Enforcement")
    print("=" * 72)
    print(
        "[INGEST] "
        f"report_path={report_path} "
        f"generated_at={report.generated_at_utc or 'n/a'} "
        f"tallies={len(report.tallies)} "
        f"active_validators={report.active_validator_count}"
    )

    jail_tallies = [tally for tally in report.tallies if tally.recommended_action == "jail"]
    warn_tallies = [tally for tally in report.tallies if tally.recommended_action == "warn"]
    maintain_tallies = [tally for tally in report.tallies if tally.recommended_action == "maintain"]

    for tally in report.tallies:
        print(
            "[INGEST] "
            f"target={tally.target_validator_address} "
            f"action={tally.recommended_action} "
            f"flags={tally.flag_votes} "
            f"endorses={tally.endorse_votes} "
            f"participation={format_ratio(tally.participation_ratio)} "
            f"flag_ratio={format_ratio(tally.flag_ratio)}"
        )

    print(
        "[PLAN] "
        f"jail_targets={len(jail_tallies)} "
        f"warn_targets={len(warn_tallies)} "
        f"maintain_targets={len(maintain_tallies)}"
    )

    failures = 0

    if jail_tallies:
        for tally in jail_tallies:
            print(
                "[ENFORCE] "
                f"target={tally.target_validator_address} "
                f"action=jail "
                f"reason={tally.threshold_reason}"
            )

        config_text = config.rippled_cfg_path.read_text()
        update = update_trusted_validators(
            config_text,
            section_name=config.trusted_validators_section,
            remove_keys=tuple(tally.target_validator_address for tally in jail_tallies),
        )

        print(f"[CONFIG] rippled_cfg_path={config.rippled_cfg_path}")
        print(f"[CONFIG] trusted_validators_before={json.dumps(list(update.before_keys))}")
        print(f"[CONFIG] trusted_validators_after={json.dumps(list(update.after_keys))}")

        if update.changed:
            config.rippled_cfg_path.write_text(update.updated_text)
            print(f"[CONFIG] write_status=updated removed={json.dumps(list(update.removed_keys))}")

            removed_lookup = set(update.removed_keys)
            for tally in jail_tallies:
                if tally.target_validator_address not in removed_lookup:
                    continue
                alert_entry = build_jail_alert_entry(tally, report_path)
                append_jsonl(config.alert_log_path, alert_entry)
                print(
                    "[ALERT] "
                    f"target={tally.target_validator_address} "
                    f"action=jail "
                    f"log_path={config.alert_log_path} "
                    f"flag_ratio={format_ratio(tally.flag_ratio)} "
                    f"participation={format_ratio(tally.participation_ratio)}"
                )

            if update.diff:
                print("[CONFIG_DIFF]")
                print(update.diff)

            command_result = run_command(config.peer_filter_reload_command)
            print(
                "[RELOAD] "
                f"command={shell_join(config.peer_filter_reload_command)} "
                f"exit_code={command_result.exit_code}"
            )
            if command_result.stdout:
                print(f"[RELOAD] stdout={command_result.stdout}")
            if command_result.stderr:
                print(f"[RELOAD] stderr={command_result.stderr}")
            if command_result.exit_code != 0:
                failures += 1
        else:
            print("[CONFIG] write_status=unchanged removed=[]")
            print("[RELOAD] skipped=no_config_change")

    for tally in warn_tallies:
        print(
            "[ENFORCE] "
            f"target={tally.target_validator_address} "
            f"action=warn "
            f"reason={tally.threshold_reason}"
        )
        alert_entry = build_warn_alert_entry(tally, report_path)
        append_jsonl(config.alert_log_path, alert_entry)
        print(
            "[ALERT] "
            f"target={tally.target_validator_address} "
            f"log_path={config.alert_log_path} "
            f"flag_ratio={format_ratio(tally.flag_ratio)} "
            f"participation={format_ratio(tally.participation_ratio)}"
        )

        recheck_entry = build_recheck_entry(tally, report_path, cooldown_minutes=config.warn_cooldown_minutes)
        append_jsonl(config.recheck_schedule_path, recheck_entry)
        print(
            "[SCHEDULE] "
            f"target={tally.target_validator_address} "
            f"recheck_not_before={recheck_entry['recheck_not_before_utc']} "
            f"cooldown_minutes={config.warn_cooldown_minutes} "
            f"schedule_path={config.recheck_schedule_path}"
        )

    for tally in maintain_tallies:
        print(
            "[NOOP] "
            f"target={tally.target_validator_address} "
            f"action=maintain "
            f"reason={tally.threshold_reason}"
        )

    return 1 if failures else 0


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Enforce governance actions from a UNL health report")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--report", required=True, help="Path to deterministic UNL health report JSON")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = load_enforcement_config(Path(args.config))
        report_path = Path(args.report)
        if not report_path.exists():
            print(f"Health report not found: {report_path}", file=sys.stderr)
            return 1

        if not config.rippled_cfg_path.exists():
            print(f"rippled.cfg not found: {config.rippled_cfg_path}", file=sys.stderr)
            return 1

        report = load_health_report(report_path)
        return enforce_governance(report, config, report_path)
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
