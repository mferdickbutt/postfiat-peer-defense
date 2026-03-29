#!/usr/bin/env python3
"""
Unit tests for the peer health signature ingestion and verification engine.
"""

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import nacl.signing
from xrpl.core import addresscodec

sys.path.insert(0, str(Path(__file__).parent))

from health_signature_ingestion import (
    IngestionConfig,
    PeerConsensusEntry,
    aggregate_consensus,
    build_ingestion_summary,
    build_simulated_health_payload,
    build_simulated_tx_entry,
    build_validator_state,
    compute_recommended_action,
    generate_simulated_validators,
    main,
    run_simulation,
)
from validator_health_signatures import (
    extract_health_signature_records,
    verify_health_signature_payload,
)


class TestSimulationPipeline(unittest.TestCase):
    def test_simulation_produces_valid_signed_records(self):
        records, raw_entries = run_simulation()
        self.assertEqual(len(records), 3)
        self.assertEqual(len(raw_entries), 3)
        for record in records:
            self.assertTrue(record.validator_signature_valid, f"Signature invalid for tx={record.tx_hash}")
            self.assertTrue(record.signing_account_matches_claim, f"Account mismatch for tx={record.tx_hash}")
            self.assertEqual(record.validation_errors, ())

    def test_simulation_records_from_distinct_validators(self):
        records, _ = run_simulation()
        validators = {
            record.payload.get("node_validator") for record in records
        }
        self.assertEqual(len(validators), 3)

    def test_simulation_payloads_pass_cryptographic_verification(self):
        records, _ = run_simulation()
        for record in records:
            verify_health_signature_payload(record.payload)


class TestBuildValidatorState(unittest.TestCase):
    def test_deduplicates_by_latest_timestamp(self):
        validators = generate_simulated_validators(1)
        v = validators[0]

        payload_old = build_simulated_health_payload(
            v,
            peer_scores=[{"wallet": "nHTarget1", "score": 0.5, "status": "endorse"}],
            actions=[],
            timestamp="2026-03-28T10:00:00Z",
        )
        payload_new = build_simulated_health_payload(
            v,
            peer_scores=[{"wallet": "nHTarget1", "score": 0.9, "status": "endorse"}],
            actions=[],
            timestamp="2026-03-28T11:00:00Z",
        )

        tx1 = build_simulated_tx_entry(v, payload_old, tx_hash="TX_OLD", ledger_index=100)
        tx2 = build_simulated_tx_entry(v, payload_new, tx_hash="TX_NEW", ledger_index=101)

        records = extract_health_signature_records(tx1) + extract_health_signature_records(tx2)
        state = build_validator_state(records)

        self.assertEqual(len(state), 1)
        entry = list(state.values())[0]
        self.assertEqual(entry["ts"], "2026-03-28T11:00:00Z")
        self.assertEqual(entry["peer_scores"][0]["score"], 0.9)

    def test_skips_invalid_signature_records(self):
        validators = generate_simulated_validators(1)
        v = validators[0]

        payload = build_simulated_health_payload(
            v,
            peer_scores=[{"wallet": "nHTarget1", "score": 0.5, "status": "endorse"}],
            actions=[],
            timestamp="2026-03-28T10:00:00Z",
        )
        tx = build_simulated_tx_entry(v, payload, tx_hash="TX1", ledger_index=100)
        records = extract_health_signature_records(tx)

        # Tamper with the record to mark it as invalid
        tampered = records[0]
        from health_signature_ingestion import HealthSignatureRecord
        bad_record = HealthSignatureRecord(
            tx_hash=tampered.tx_hash,
            account=tampered.account,
            ledger_index=tampered.ledger_index,
            validated=tampered.validated,
            payload=tampered.payload,
            source=tampered.source,
            signing_account_matches_claim=tampered.signing_account_matches_claim,
            validator_signature_valid=False,
            validation_errors=("tampered",),
        )
        state = build_validator_state([bad_record])
        self.assertEqual(len(state), 0)


class TestAggregateConsensus(unittest.TestCase):
    def setUp(self):
        self.config = IngestionConfig()

    def test_maintain_action_for_high_scores(self):
        state = {
            "nHVal1": {
                "peer_scores": [{"wallet": "nHTarget", "score": 0.9, "status": "endorse"}],
            },
            "nHVal2": {
                "peer_scores": [{"wallet": "nHTarget", "score": 0.8, "status": "endorse"}],
            },
        }
        entries = aggregate_consensus(state, self.config)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].recommended_action, "maintain")
        self.assertAlmostEqual(entries[0].avg_score, 0.85, places=2)

    def test_warn_action_for_mixed_scores(self):
        state = {
            "nHVal1": {
                "peer_scores": [{"wallet": "nHTarget", "score": 0.3, "status": "flag"}],
            },
            "nHVal2": {
                "peer_scores": [{"wallet": "nHTarget", "score": 0.1, "status": "flag"}],
            },
        }
        entries = aggregate_consensus(state, self.config)
        self.assertEqual(entries[0].recommended_action, "warn")

    def test_escalate_action_for_low_scores(self):
        state = {
            "nHVal1": {
                "peer_scores": [{"wallet": "nHTarget", "score": -0.8, "status": "jail"}],
            },
            "nHVal2": {
                "peer_scores": [{"wallet": "nHTarget", "score": -0.6, "status": "jail"}],
            },
        }
        entries = aggregate_consensus(state, self.config)
        self.assertEqual(entries[0].recommended_action, "escalate")
        self.assertEqual(entries[0].flags, 2)

    def test_multiple_targets_sorted(self):
        state = {
            "nHVal1": {
                "peer_scores": [
                    {"wallet": "nHBBB", "score": 0.9, "status": "endorse"},
                    {"wallet": "nHAAA", "score": -0.9, "status": "jail"},
                ],
            },
        }
        entries = aggregate_consensus(state, self.config)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].target_address, "nHAAA")
        self.assertEqual(entries[1].target_address, "nHBBB")


class TestComputeRecommendedAction(unittest.TestCase):
    def test_boundary_at_warn_threshold(self):
        config = IngestionConfig(warn_score_threshold=0.5, escalate_score_threshold=-0.5)
        action, _ = compute_recommended_action(0.5, config)
        self.assertEqual(action, "maintain")
        action, _ = compute_recommended_action(0.49, config)
        self.assertEqual(action, "warn")

    def test_boundary_at_escalate_threshold(self):
        config = IngestionConfig(warn_score_threshold=0.5, escalate_score_threshold=-0.5)
        action, _ = compute_recommended_action(-0.5, config)
        self.assertEqual(action, "warn")
        action, _ = compute_recommended_action(-0.51, config)
        self.assertEqual(action, "escalate")


class TestCLISimulate(unittest.TestCase):
    def test_simulate_exits_zero_with_output(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--simulate"])
        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("[INGEST]", output)
        self.assertIn("[VERIFY]", output)
        self.assertIn("[CONSENSUS]", output)
        self.assertIn("Multi-Node UNL Quality Summary", output)
        self.assertIn("maintain", output)
        self.assertIn("warn", output)
        self.assertIn("escalate", output)
        # At least 3 VERIFY lines
        verify_lines = [line for line in output.splitlines() if line.startswith("[VERIFY] tx=")]
        self.assertGreaterEqual(len(verify_lines), 3)
        # All signatures pass
        for line in verify_lines:
            self.assertIn("signature=PASS", line)

    def test_simulate_json_out(self):
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--simulate", "--json-out", json_path])

        self.assertEqual(exit_code, 0)
        data = json.loads(Path(json_path).read_text())
        self.assertIn("consensus_entries", data)
        self.assertGreaterEqual(len(data["consensus_entries"]), 3)
        Path(json_path).unlink()


if __name__ == "__main__":
    unittest.main()
