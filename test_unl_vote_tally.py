#!/usr/bin/env python3
"""
Unit tests for the UNL vote aggregation and tally module.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from unl_vote_tally import (
    TallyConfig,
    aggregate_votes,
    build_simulated_vote_transactions,
    load_vote_transactions,
    main,
)


class UnlVoteTallyTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_json(self, filename: str, payload: object) -> Path:
        path = self.temp_path / filename
        path.write_text(json.dumps(payload, indent=2))
        return path

    def test_load_vote_transactions_from_simulated_xrpl_payloads(self):
        path = self._write_json("simulated-votes.json", build_simulated_vote_transactions())

        votes, warnings = load_vote_transactions(path)

        self.assertEqual(len(votes), 6)
        self.assertEqual(len({vote.voter_validator_address for vote in votes}), 4)
        self.assertEqual(len({vote.target_validator_address for vote in votes}), 2)
        self.assertEqual(warnings, [])

    def test_load_vote_transactions_from_direct_payloads(self):
        direct_payloads = [
            {
                "schema": "postfiat.unl_vote.v1",
                "voter_validator_public_key": "nHValidatorOne",
                "peer_validator_public_key": "nHTargetOne",
                "verdict": "flag",
                "evaluated_at": "2026-03-24T00:00:00Z",
                "validator_signature": "AB" * 64,
            },
            {
                "schema": "postfiat.unl_vote.v1",
                "voter_validator_public_key": "nHValidatorTwo",
                "peer_validator_public_key": "nHTargetOne",
                "verdict": "endorse",
                "evaluated_at": "2026-03-24T00:01:00Z",
                "validator_signature": "CD" * 64,
            },
        ]
        path = self._write_json("direct-payloads.json", direct_payloads)

        votes, warnings = load_vote_transactions(path)

        self.assertEqual(len(votes), 2)
        self.assertEqual(votes[0].decision, "flag")
        self.assertEqual(votes[1].decision, "endorse")
        self.assertEqual(warnings, [])

    def test_aggregate_votes_deduplicates_latest_vote_per_voter_and_target(self):
        duplicate_votes = [
            {
                "schema": "postfiat.unl_vote.v1",
                "voter_validator_public_key": "nHValidatorOne",
                "peer_validator_public_key": "nHTargetOne",
                "verdict": "endorse",
                "evaluated_at": "2026-03-24T00:00:00Z",
                "validator_signature": "AA" * 64,
            },
            {
                "schema": "postfiat.unl_vote.v1",
                "voter_validator_public_key": "nHValidatorOne",
                "peer_validator_public_key": "nHTargetOne",
                "verdict": "flag",
                "evaluated_at": "2026-03-24T00:05:00Z",
                "validator_signature": "BB" * 64,
            },
            {
                "schema": "postfiat.unl_vote.v1",
                "voter_validator_public_key": "nHValidatorTwo",
                "peer_validator_public_key": "nHTargetOne",
                "verdict": "flag",
                "evaluated_at": "2026-03-24T00:06:00Z",
                "validator_signature": "CC" * 64,
            },
        ]
        path = self._write_json("duplicate-votes.json", duplicate_votes)
        votes, _warnings = load_vote_transactions(path)

        report = aggregate_votes(votes, TallyConfig())

        self.assertEqual(report.ingested_vote_count, 3)
        self.assertEqual(report.deduped_vote_count, 2)
        self.assertEqual(report.tallies[0].flag_votes, 2)
        self.assertEqual(report.tallies[0].endorse_votes, 0)

    def test_aggregate_votes_generates_jail_and_maintain_actions(self):
        path = self._write_json("simulated-votes.json", build_simulated_vote_transactions())
        votes, _warnings = load_vote_transactions(path)

        report = aggregate_votes(votes, TallyConfig())
        actions = {tally.target_validator_address: tally.recommended_action for tally in report.tallies}

        self.assertEqual(actions["nHTargetPeerBlue2222222222222222222222222"], "maintain")
        self.assertEqual(actions["nHTargetPeerRed11111111111111111111111111"], "jail")

    def test_cli_simulation_output_contains_ingest_tally_and_report(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--simulate"])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("[INGEST] valid_vote_memos=6", output)
        self.assertIn("[TALLY] target=nHTargetPeerRed11111111111111111111111111 flags=3 endorses=0", output)
        self.assertIn("[REPORT] target=nHTargetPeerRed11111111111111111111111111 action=jail", output)

    def test_cli_can_write_machine_readable_health_report(self):
        report_path = self.temp_path / "health-report.json"

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--simulate", "--report-out", str(report_path)])

        output = stdout.getvalue()
        written_report = json.loads(report_path.read_text())

        self.assertEqual(exit_code, 0)
        self.assertTrue(report_path.exists())
        self.assertIn("[REPORT] json_path=", output)
        self.assertIn("generated_at_utc", written_report)
        self.assertEqual(written_report["ingested_vote_count"], 6)
        self.assertEqual(written_report["tallies"][0]["recommended_action"], "maintain")
        self.assertEqual(written_report["tallies"][1]["recommended_action"], "jail")


if __name__ == "__main__":
    unittest.main()
