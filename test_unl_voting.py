#!/usr/bin/env python3
"""
Unit tests for the UNL peer health voting module.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import nacl.signing
from xrpl.constants import CryptoAlgorithm
from xrpl.core import addresscodec
from xrpl.wallet import Wallet

sys.path.insert(0, str(Path(__file__).parent))

from unl_voting import (
    DEFAULT_MEMO_SCHEMA,
    build_dry_run_transaction,
    build_vote_artifacts,
    evaluate_peer,
    load_peer_records,
    load_validator_identity,
    load_voting_config,
    submit_vote_transaction,
    verify_validator_signature,
)


class UnlVotingTestCase(unittest.TestCase):
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

        self.config_path = self.temp_path / "config.json"
        self.config_path.write_text(
            json.dumps(
                {
                    "thresholds": {
                        "peer_count_floor": 5,
                        "scoring_latency_ceiling_ms": 500,
                        "ledger_sync_lag_max_seconds": 30,
                        "sustained_breach_intervals": 3,
                    },
                    "monitoring": {
                        "poll_interval_seconds": 30,
                        "log_path": str(self.temp_path / "defense.log"),
                    },
                    "response": {
                        "peer_reconnect_attempts": 3,
                        "firewall_ban_duration_minutes": 60,
                    },
                    "postfiatd": {
                        "host": "127.0.0.1",
                        "port": 5005,
                    },
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
                }
            )
        )

        self.config = load_voting_config(self.config_path)
        self.validator_identity = load_validator_identity(self.validator_keys_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_jsonl(self, filename: str, lines: list[str]) -> Path:
        path = self.temp_path / filename
        path.write_text("\n".join(lines))
        return path

    def test_load_peer_records_from_jsonl(self):
        path = self._write_jsonl(
            "peers.jsonl",
            [
                json.dumps(
                    {
                        "validator_public_key": "nHHealthyJSONL",
                        "uptime_pct": 99.1,
                        "scoring_latency_ms": 101,
                        "consensus_participation_pct": 98.2,
                        "last_seen_utc": "2035-01-01T00:00:00Z",
                    }
                ),
                json.dumps(
                    {
                        "validator_public_key": "nHFlaggedJSONL",
                        "uptime_pct": 92.0,
                        "scoring_latency_ms": 801,
                        "consensus_participation_pct": 80.0,
                        "last_seen_utc": "2026-03-20T00:00:00Z",
                    }
                ),
            ],
        )

        records, warnings = load_peer_records(path)

        self.assertEqual(len(records), 2)
        self.assertEqual(warnings, [])
        self.assertAlmostEqual(records[0].uptime_pct, 0.991)
        self.assertAlmostEqual(records[1].consensus_participation_pct, 0.8)

    def test_load_peer_records_from_json_array(self):
        path = self.temp_path / "peers.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "validator_public_key": "nHArrayPeer",
                        "uptime_pct": 0.99,
                        "scoring_latency_ms": 75,
                        "consensus_participation_pct": 0.98,
                        "last_seen_utc": "2035-01-01T00:00:00Z",
                    }
                ]
            )
        )

        records, warnings = load_peer_records(path)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].validator_public_key, "nHArrayPeer")
        self.assertEqual(warnings, [])

    def test_load_peer_records_skips_malformed_records(self):
        path = self._write_jsonl(
            "bad-peers.jsonl",
            [
                "{not-json}",
                json.dumps(
                    {
                        "validator_public_key": "nHValidPeer",
                        "uptime_pct": 99.0,
                        "scoring_latency_ms": 90,
                        "consensus_participation_pct": 99.0,
                        "last_seen_utc": "2035-01-01T00:00:00Z",
                    }
                ),
                json.dumps(
                    {
                        "validator_public_key": "nHMissingLatency",
                        "uptime_pct": 99.0,
                        "consensus_participation_pct": 99.0,
                        "last_seen_utc": "2035-01-01T00:00:00Z",
                    }
                ),
            ],
        )

        records, warnings = load_peer_records(path)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].validator_public_key, "nHValidPeer")
        self.assertEqual(len(warnings), 2)
        self.assertIn("invalid JSON", warnings[0])
        self.assertIn("scoring_latency_ms", warnings[1])

    def test_evaluate_peer_endorse(self):
        record = load_peer_records(
            self._write_jsonl(
                "healthy.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHEndorse",
                            "uptime_pct": 99.2,
                            "scoring_latency_ms": 75,
                            "consensus_participation_pct": 98.1,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]

        decision = evaluate_peer(record, self.config)

        self.assertEqual(decision.verdict, "endorse")
        self.assertEqual(decision.breaches, [])

    def test_evaluate_peer_flags_uptime(self):
        record = load_peer_records(
            self._write_jsonl(
                "uptime.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHFlagUptime",
                            "uptime_pct": 90.0,
                            "scoring_latency_ms": 75,
                            "consensus_participation_pct": 98.1,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]

        decision = evaluate_peer(record, self.config)

        self.assertEqual(decision.verdict, "flag")
        self.assertIn("uptime_below_min", decision.breaches)

    def test_evaluate_peer_flags_latency(self):
        record = load_peer_records(
            self._write_jsonl(
                "latency.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHFlagLatency",
                            "uptime_pct": 99.0,
                            "scoring_latency_ms": 1000,
                            "consensus_participation_pct": 98.1,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]

        decision = evaluate_peer(record, self.config)

        self.assertIn("latency_above_max", decision.breaches)

    def test_evaluate_peer_flags_consensus(self):
        record = load_peer_records(
            self._write_jsonl(
                "consensus.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHFlagConsensus",
                            "uptime_pct": 99.0,
                            "scoring_latency_ms": 100,
                            "consensus_participation_pct": 80.0,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]

        decision = evaluate_peer(record, self.config)

        self.assertIn("consensus_below_min", decision.breaches)

    def test_evaluate_peer_flags_stale_last_seen(self):
        record = load_peer_records(
            self._write_jsonl(
                "stale.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHFlagStale",
                            "uptime_pct": 99.0,
                            "scoring_latency_ms": 100,
                            "consensus_participation_pct": 98.0,
                            "last_seen_utc": "2026-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]

        decision = evaluate_peer(record, self.config)

        self.assertIn("last_seen_stale", decision.breaches)

    def test_vote_signature_verifies_and_memo_schema_is_correct(self):
        record = load_peer_records(
            self._write_jsonl(
                "memo.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHVoteMemoPeer",
                            "uptime_pct": 99.0,
                            "scoring_latency_ms": 100,
                            "consensus_participation_pct": 98.0,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]

        decision = evaluate_peer(record, self.config)
        with patch(
            "unl_voting.sign_with_validator_key",
            side_effect=lambda message, _identity: self.signing_key.sign(message.encode("utf-8")).signature.hex().upper(),
        ):
            vote_artifacts = build_vote_artifacts(decision, self.validator_identity)
        canonical_json = json.dumps(vote_artifacts.canonical_payload, sort_keys=True, separators=(",", ":"))

        self.assertEqual(vote_artifacts.signed_payload["schema"], DEFAULT_MEMO_SCHEMA)
        verify_validator_signature(canonical_json, vote_artifacts.signed_payload["validator_signature"], self.validator_identity)
        self.assertEqual(vote_artifacts.memo.memo_type, DEFAULT_MEMO_SCHEMA.encode("utf-8").hex().upper())

    def test_dry_run_transaction_builds_accountset_with_memo(self):
        fee_payer_wallet = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        record = load_peer_records(
            self._write_jsonl(
                "dryrun.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHDryRunPeer",
                            "uptime_pct": 99.0,
                            "scoring_latency_ms": 100,
                            "consensus_participation_pct": 98.0,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]
        decision = evaluate_peer(record, self.config)
        with patch(
            "unl_voting.sign_with_validator_key",
            side_effect=lambda message, _identity: self.signing_key.sign(message.encode("utf-8")).signature.hex().upper(),
        ):
            vote_artifacts = build_vote_artifacts(decision, self.validator_identity)

        fake_client = MagicMock()
        fake_client.request.side_effect = [
            MagicMock(result={"info": {"network_id": 21338, "validated_ledger": {"seq": 7654321}}}),
            Exception("Account does not exist yet"),
        ]

        wallet_context = type("WalletContext", (), {"wallet": fee_payer_wallet})()
        signed_payment, metadata, sequence_source = build_dry_run_transaction(
            fake_client, wallet_context, vote_artifacts.memo
        )

        self.assertEqual(signed_payment.account, fee_payer_wallet.address)
        self.assertEqual(signed_payment.sequence, 0)
        self.assertEqual(metadata.network_id, 21338)
        self.assertEqual(sequence_source, "fallback_zero")
        self.assertEqual(len(signed_payment.memos), 1)
        self.assertTrue(signed_payment.is_signed())

    def test_submit_path_is_mockable(self):
        fee_payer_wallet = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        record = load_peer_records(
            self._write_jsonl(
                "submit.jsonl",
                [
                    json.dumps(
                        {
                            "validator_public_key": "nHSubmitPeer",
                            "uptime_pct": 99.0,
                            "scoring_latency_ms": 100,
                            "consensus_participation_pct": 98.0,
                            "last_seen_utc": "2035-01-01T00:00:00Z",
                        }
                    )
                ],
            )
        )[0][0]
        decision = evaluate_peer(record, self.config)
        with patch(
            "unl_voting.sign_with_validator_key",
            side_effect=lambda message, _identity: self.signing_key.sign(message.encode("utf-8")).signature.hex().upper(),
        ):
            vote_artifacts = build_vote_artifacts(decision, self.validator_identity)
        fake_client = MagicMock()
        fake_client.request.return_value = MagicMock(result={"info": {"network_id": 31337, "validated_ledger": {"seq": 123}}})

        with patch("unl_voting.submit_and_wait") as mock_submit:
            mock_submit.return_value = MagicMock(result={"hash": "ABC123", "engine_result": "tesSUCCESS"})
            result = submit_vote_transaction(
                fake_client,
                type("WalletContext", (), {"wallet": fee_payer_wallet})(),
                vote_artifacts.memo,
            )

        self.assertEqual(result["transaction_hash"], "ABC123")
        self.assertEqual(result["engine_result"], "tesSUCCESS")
        submitted_payment = mock_submit.call_args.args[0]
        self.assertEqual(submitted_payment.account, fee_payer_wallet.address)
        self.assertEqual(submitted_payment.network_id, 31337)


if __name__ == "__main__":
    unittest.main()
