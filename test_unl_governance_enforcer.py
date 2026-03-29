#!/usr/bin/env python3
"""
Unit tests for deterministic UNL governance enforcement.
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from unl_governance_enforcer import main, update_trusted_validators


class UnlGovernanceEnforcerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_json(self, filename: str, payload: object) -> Path:
        path = self.temp_path / filename
        path.write_text(json.dumps(payload, indent=2))
        return path

    def _write_text(self, filename: str, content: str) -> Path:
        path = self.temp_path / filename
        path.write_text(content)
        return path

    def test_update_trusted_validators_removes_and_adds_keys(self):
        config_text = """[server]
port_rpc_admin_local

[validators]
# trusted validators
nHJailedValidator111111111111111111111111111
nHWarnedValidator222222222222222222222222222

[validator_list_sites]
https://vl.postfiat.example
"""

        update = update_trusted_validators(
            config_text,
            section_name="validators",
            remove_keys=("nHJailedValidator111111111111111111111111111",),
            add_keys=("nHReplacementValidator3333333333333333333333333",),
        )

        self.assertTrue(update.changed)
        self.assertEqual(
            update.before_keys,
            (
                "nHJailedValidator111111111111111111111111111",
                "nHWarnedValidator222222222222222222222222222",
            ),
        )
        self.assertEqual(
            update.after_keys,
            (
                "nHWarnedValidator222222222222222222222222222",
                "nHReplacementValidator3333333333333333333333333",
            ),
        )
        self.assertIn("-nHJailedValidator111111111111111111111111111", update.diff)
        self.assertIn("+nHReplacementValidator3333333333333333333333333", update.diff)
        self.assertIn("# trusted validators", update.updated_text)

    def test_cli_enforces_jail_and_warn_actions(self):
        jailed_validator = "nHJailedValidator111111111111111111111111111"
        warned_validator = "nHWarnedValidator222222222222222222222222222"
        healthy_validator = "nHHealthyValidator3333333333333333333333333"

        rippled_cfg_path = self._write_text(
            "rippled.cfg",
            f"""[server]
port_rpc_admin_local

[validators]
{jailed_validator}
{warned_validator}
{healthy_validator}

[validator_list_sites]
https://vl.postfiat.example
""",
        )

        alert_log_path = self.temp_path / "alerts.jsonl"
        recheck_schedule_path = self.temp_path / "rechecks.jsonl"
        config_path = self._write_json(
            "config.json",
            {
                "unl_enforcement": {
                    "rippled_cfg_path": str(rippled_cfg_path),
                    "trusted_validators_section": "validators",
                    "peer_filter_reload_command": [sys.executable, "-c", "print('peer-filtering-reloaded')"],
                    "warn_cooldown_minutes": 90,
                    "alert_log_path": str(alert_log_path),
                    "recheck_schedule_path": str(recheck_schedule_path),
                }
            },
        )

        report_path = self._write_json(
            "health-report.json",
            {
                "generated_at_utc": "2026-03-24T00:30:00Z",
                "ingested_vote_count": 9,
                "deduped_vote_count": 9,
                "active_validator_count": 4,
                "tallies": [
                    {
                        "target_validator_address": jailed_validator,
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
                        "threshold_reason": "jail threshold met: flag ratio 100.00% > 66.67%",
                    },
                    {
                        "target_validator_address": warned_validator,
                        "flag_votes": 1,
                        "endorse_votes": 1,
                        "total_votes": 2,
                        "voters_participating": 3,
                        "active_validator_count": 4,
                        "participation_ratio": 0.75,
                        "flag_ratio": 0.5,
                        "endorse_ratio": 0.5,
                        "quorum_met": True,
                        "recommended_action": "warn",
                        "threshold_reason": "warn threshold met: flag ratio 50.00% >= 50.00%",
                    },
                    {
                        "target_validator_address": healthy_validator,
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
                        "threshold_reason": "maintain threshold met: flag ratio 0.00% < 50.00%",
                    },
                ],
            },
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--config", str(config_path), "--report", str(report_path)])

        output = stdout.getvalue()
        updated_cfg = rippled_cfg_path.read_text()
        alert_entries = [json.loads(line) for line in alert_log_path.read_text().splitlines() if line.strip()]
        recheck_entries = [json.loads(line) for line in recheck_schedule_path.read_text().splitlines() if line.strip()]

        self.assertEqual(exit_code, 0)
        self.assertIn(f"[INGEST] report_path={report_path}", output)
        self.assertIn("[CONFIG] write_status=updated", output)
        self.assertIn(f"-{jailed_validator}", output)
        self.assertIn("[RELOAD] stdout=peer-filtering-reloaded", output)
        self.assertIn(f"[SCHEDULE] target={warned_validator}", output)
        self.assertIn(f"[NOOP] target={healthy_validator}", output)

        self.assertNotIn(jailed_validator, updated_cfg)
        self.assertIn(warned_validator, updated_cfg)
        self.assertIn(healthy_validator, updated_cfg)

        self.assertEqual(len(alert_entries), 2)
        alert_events = {entry["event"]: entry for entry in alert_entries}
        self.assertEqual(alert_events["UNL_JAIL_ENFORCED"]["target_validator_address"], jailed_validator)
        self.assertEqual(alert_events["UNL_WARN_ALERT"]["target_validator_address"], warned_validator)

        self.assertEqual(len(recheck_entries), 1)
        self.assertEqual(recheck_entries[0]["event"], "UNL_WARN_RECHECK_SCHEDULED")
        self.assertEqual(recheck_entries[0]["target_validator_address"], warned_validator)
        self.assertEqual(recheck_entries[0]["cooldown_minutes"], 90)
        self.assertIn("recheck_not_before_utc", recheck_entries[0])


if __name__ == "__main__":
    unittest.main()
