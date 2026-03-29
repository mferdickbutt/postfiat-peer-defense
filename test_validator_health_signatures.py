#!/usr/bin/env python3
"""
Unit tests for validator health signature aggregation and broadcast.
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import nacl.signing
from xrpl.core import addresscodec

sys.path.insert(0, str(Path(__file__).parent))

from unl_governance_enforcer import main as governance_main
from unl_voting import load_validator_identity
from validator_health_signatures import (
    aggregate_health_signature_payload,
    build_health_signature_artifacts,
    extract_health_signature_records,
    verify_health_signature_payload,
)


class ValidatorHealthSignaturesTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        self.signing_key = nacl.signing.SigningKey.generate()
        validator_public_key = addresscodec.encode_node_public_key(b"\xed" + bytes(self.signing_key.verify_key))

        self.validator_keys_path = self.temp_path / "validator-keys.json"
        self.validator_keys_path.write_text(
            json.dumps(
                {
                    "key_type": "ed25519",
                    "manifest": "test-manifest",
                    "public_key": validator_public_key,
                    "secret_key": "pnTestValidatorSecretKeyPlaceholder",
                    "revoked": False,
                    "token_sequence": 1,
                }
            )
        )
        self.validator_identity = load_validator_identity(self.validator_keys_path)

        self.alert_log_path = self.temp_path / "alerts.jsonl"
        self.recheck_schedule_path = self.temp_path / "rechecks.jsonl"
        self.rippled_cfg_path = self.temp_path / "postfiatd.cfg"
        self.validators_file_path = self.temp_path / "validators.txt"
        self.report_path = self.temp_path / "health-report.json"
        self.config_path = self.temp_path / "config.json"

        self.validators_file_path.write_text(
            """[validators]\nnHHealthyValidator3333333333333333333333333\n\n[validator_list_sites]\nhttps://vl.postfiat.example\n\n[validator_list_keys]\nED3F1E0DA736FCF99BE2880A60DBD470715C0E04DD793FB862236B070571FC09E2\n\n[validator_list_threshold]\n1\n"""
        )
        self.rippled_cfg_path.write_text("[validators_file]\nvalidators.txt\n")
        self.report_path.write_text(
            json.dumps(
                {
                    "generated_at_utc": "2026-03-24T00:30:00Z",
                    "ingested_vote_count": 9,
                    "deduped_vote_count": 9,
                    "active_validator_count": 4,
                    "tallies": [
                        {
                            "target_validator_address": "nHJailedValidator111111111111111111111111111",
                            "flag_votes": 3,
                            "endorse_votes": 0,
                            "total_votes": 3,
                            "voters_participating": 3,
                            "active_validator_count": 4,
                            "participation_ratio": 0.75,
                            "flag_ratio": 1.0,
                            "endorse_ratio": 0.0,
                            "quorum_met": True,
                            "recommended_action": "jail",
                            "threshold_reason": "jail threshold met",
                        },
                        {
                            "target_validator_address": "nHWarnedValidator222222222222222222222222222",
                            "flag_votes": 2,
                            "endorse_votes": 1,
                            "total_votes": 3,
                            "voters_participating": 3,
                            "active_validator_count": 4,
                            "participation_ratio": 0.75,
                            "flag_ratio": 0.6666666666666666,
                            "endorse_ratio": 0.3333333333333333,
                            "quorum_met": True,
                            "recommended_action": "warn",
                            "threshold_reason": "warn threshold met",
                        },
                        {
                            "target_validator_address": "nHHealthyValidator3333333333333333333333333",
                            "flag_votes": 0,
                            "endorse_votes": 3,
                            "total_votes": 3,
                            "voters_participating": 3,
                            "active_validator_count": 4,
                            "participation_ratio": 0.75,
                            "flag_ratio": 0.0,
                            "endorse_ratio": 1.0,
                            "quorum_met": True,
                            "recommended_action": "maintain",
                            "threshold_reason": "maintain threshold met",
                        },
                    ],
                }
            )
        )
        self.alert_log_path.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "timestamp": "2026-03-24T00:31:00Z",
                            "event": "UNL_JAIL_ENFORCED",
                            "target_validator_address": "nHJailedValidator111111111111111111111111111",
                            "recommended_action": "jail",
                            "flag_votes": 3,
                            "endorse_votes": 0,
                            "total_votes": 3,
                            "flag_ratio": 1.0,
                            "participation_ratio": 0.75,
                            "threshold_reason": "jail threshold met",
                            "report_path": str(self.report_path),
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-03-24T00:32:00Z",
                            "event": "UNL_WARN_ALERT",
                            "target_validator_address": "nHWarnedValidator222222222222222222222222222",
                            "recommended_action": "warn",
                            "flag_votes": 2,
                            "endorse_votes": 1,
                            "total_votes": 3,
                            "flag_ratio": 0.6666666666666666,
                            "participation_ratio": 0.75,
                            "threshold_reason": "warn threshold met",
                            "report_path": str(self.report_path),
                        }
                    ),
                ]
            )
            + "\n"
        )
        self.config_path.write_text(
            json.dumps(
                {
                    "unl_voting": {
                        "uptime_min_pct": 0.98,
                        "latency_max_ms": 500,
                        "consensus_min_pct": 0.95,
                        "last_seen_max_age_seconds": 900,
                        "xrpl_rpc_url": "http://127.0.0.1:5005",
                        "validator_keys_path": str(self.validator_keys_path),
                        "fee_payer_seed_env": "XRPL_FEE_PAYER_SEED",
                        "dry_run_default": True,
                    },
                    "unl_enforcement": {
                        "rippled_cfg_path": str(self.rippled_cfg_path),
                        "trusted_validators_section": "validators",
                        "peer_filter_reload_command": [sys.executable, "-c", "print('peer-filtering-reloaded')"],
                        "warn_cooldown_minutes": 90,
                        "alert_log_path": str(self.alert_log_path),
                        "recheck_schedule_path": str(self.recheck_schedule_path),
                    },
                }
            )
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_aggregate_health_signature_payload_includes_peer_scores_actions_and_unl_state(self):
        payload, warnings = aggregate_health_signature_payload(
            self.report_path,
            node_wallet_address="rTestNodeWallet111111111111111111111",
            node_validator_public_key=self.validator_identity.validator_public_key,
            config_path=self.config_path,
            alert_log_path=self.alert_log_path,
            recent_actions_limit=10,
            rippled_cfg_path=self.rippled_cfg_path,
            validators_file_path=None,
            docker_container="postfiatd",
        )

        self.assertEqual(warnings, [])
        self.assertEqual(payload["node_wallet"], "rTestNodeWallet111111111111111111111")
        self.assertEqual(len(payload["peer_scores"]), 3)
        self.assertEqual(payload["peer_scores"][0]["status"], "endorse")
        self.assertEqual(payload["peer_scores"][1]["status"], "jail")
        self.assertEqual(payload["peer_scores"][2]["status"], "flag")
        self.assertEqual(len(payload["actions"]), 2)
        self.assertEqual(payload["actions"][0]["action"], "jail")
        self.assertEqual(payload["actions"][1]["action"], "warn")
        self.assertEqual(payload["local_unl"]["validators"], 1)
        self.assertEqual(payload["local_unl"]["sites"], 1)
        self.assertEqual(payload["local_unl"]["keys"], 1)
        self.assertTrue(payload["local_unl"]["hash"])
    def test_signed_memo_round_trip_validates_account_and_signature(self):
        payload, _warnings = aggregate_health_signature_payload(
            self.report_path,
            node_wallet_address="rTestNodeWallet111111111111111111111",
            node_validator_public_key=self.validator_identity.validator_public_key,
            config_path=self.config_path,
            alert_log_path=self.alert_log_path,
            recent_actions_limit=10,
            rippled_cfg_path=self.rippled_cfg_path,
            validators_file_path=None,
            docker_container="postfiatd",
        )
        with patch(
            "validator_health_signatures.sign_with_validator_key",
            side_effect=lambda message, _identity: self.signing_key.sign(message.encode("utf-8")).signature.hex().upper(),
        ):
            artifacts = build_health_signature_artifacts(payload, self.validator_identity)

        verify_health_signature_payload(artifacts.signed_payload)
        tx_entry = {
            "hash": "ABC123",
            "ledger_index": 7654321,
            "validated": True,
            "tx": {
                "Account": "rTestNodeWallet111111111111111111111",
                "Memos": [
                    {
                        "Memo": {
                            "MemoData": artifacts.memo.memo_data,
                            "MemoType": artifacts.memo.memo_type,
                            "MemoFormat": artifacts.memo.memo_format,
                        }
                    }
                ],
            },
        }

        records = extract_health_signature_records(tx_entry)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].tx_hash, "ABC123")
        self.assertTrue(records[0].signing_account_matches_claim)
        self.assertTrue(records[0].validator_signature_valid)
        self.assertEqual(records[0].payload["node_wallet"], "rTestNodeWallet111111111111111111111")

    def test_governance_enforcer_logs_jail_and_warn_alerts(self):
        jailed_validator = "nHJailedValidator111111111111111111111111111"
        warned_validator = "nHWarnedValidator222222222222222222222222222"
        healthy_validator = "nHHealthyValidator3333333333333333333333333"

        pre_enforcement_cfg_path = self.temp_path / "enforcer-rippled.cfg"
        pre_enforcement_cfg_path.write_text(
            f"""[server]\nport_rpc_admin_local\n\n[validators]\n{jailed_validator}\n{warned_validator}\n{healthy_validator}\n\n[validator_list_sites]\nhttps://vl.postfiat.example\n"""
        )
        alert_log_path = self.temp_path / "enforcer-alerts.jsonl"
        recheck_schedule_path = self.temp_path / "enforcer-rechecks.jsonl"
        enforcer_config_path = self.temp_path / "enforcer-config.json"
        enforcer_report_path = self.temp_path / "enforcer-report.json"

        enforcer_config_path.write_text(
            json.dumps(
                {
                    "unl_enforcement": {
                        "rippled_cfg_path": str(pre_enforcement_cfg_path),
                        "trusted_validators_section": "validators",
                        "peer_filter_reload_command": [sys.executable, "-c", "print('peer-filtering-reloaded')"],
                        "warn_cooldown_minutes": 90,
                        "alert_log_path": str(alert_log_path),
                        "recheck_schedule_path": str(recheck_schedule_path),
                    }
                }
            )
        )
        enforcer_report_path.write_text(self.report_path.read_text())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = governance_main(["--config", str(enforcer_config_path), "--report", str(enforcer_report_path)])

        alert_entries = [json.loads(line) for line in alert_log_path.read_text().splitlines() if line.strip()]
        events = {entry["event"] for entry in alert_entries}
        output = stdout.getvalue()

        self.assertEqual(exit_code, 0)
        self.assertIn("UNL_JAIL_ENFORCED", events)
        self.assertIn("UNL_WARN_ALERT", events)
        self.assertIn("action=jail", output)
        self.assertIn("action=warn", output)


if __name__ == "__main__":
    unittest.main()