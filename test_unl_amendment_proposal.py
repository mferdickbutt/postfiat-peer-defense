#!/usr/bin/env python3
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

import nacl.signing
from xrpl.constants import CryptoAlgorithm
from xrpl.core import addresscodec
from xrpl.wallet import Wallet

sys.path.insert(0, str(Path(__file__).parent))

from unl_amendment_proposal import (
    AmendmentConfig,
    AmendmentProposal,
    PeerContribution,
    ScoreSummary,
    SignedAmendmentProposal,
    amendment_proposal_to_dict,
    build_amendment_memo_payload,
    build_amendment_proposals,
    build_score_summary,
    evaluate_quorum,
    generate_simulation,
    load_consensus_summary,
    main as amendment_main,
    map_consensus_action_to_amendment,
    sign_amendment_proposal,
)


class TestQuorumEvaluation(unittest.TestCase):
    def setUp(self):
        self.config = AmendmentConfig()

    def test_quorum_met_when_all_three_agree(self):
        contributions = (
            PeerContribution("nHVal1", -0.8, "jail", "SIG1"),
            PeerContribution("nHVal2", -0.9, "jail", "SIG2"),
            PeerContribution("nHVal3", -0.7, "jail", "SIG3"),
        )
        result = evaluate_quorum("remove", contributions, self.config)
        self.assertTrue(result.quorum_met)
        self.assertAlmostEqual(result.agreement_ratio, 1.0)

    def test_quorum_not_met_when_below_two_thirds(self):
        contributions = (
            PeerContribution("nHVal1", -0.8, "jail", "SIG1"),
            PeerContribution("nHVal2", 0.9, "endorse", "SIG2"),
            PeerContribution("nHVal3", 0.9, "endorse", "SIG3"),
        )
        result = evaluate_quorum("remove", contributions, self.config)
        self.assertFalse(result.quorum_met)
        self.assertAlmostEqual(result.agreement_ratio, 1 / 3, places=5)

    def test_quorum_exactly_two_thirds_not_met_requires_strictly_greater(self):
        contributions = (
            PeerContribution("nHVal1", -0.8, "jail", "SIG1"),
            PeerContribution("nHVal2", -0.9, "jail", "SIG2"),
            PeerContribution("nHVal3", 0.9, "endorse", "SIG3"),
        )
        result = evaluate_quorum("remove", contributions, self.config)
        self.assertFalse(result.quorum_met)
        self.assertAlmostEqual(result.agreement_ratio, 2 / 3, places=5)

    def test_quorum_with_five_peers_four_agree(self):
        contributions = (
            PeerContribution("nHVal1", -0.8, "jail", "SIG1"),
            PeerContribution("nHVal2", -0.9, "jail", "SIG2"),
            PeerContribution("nHVal3", -0.7, "jail", "SIG3"),
            PeerContribution("nHVal4", -0.6, "jail", "SIG4"),
            PeerContribution("nHVal5", 0.8, "endorse", "SIG5"),
        )
        result = evaluate_quorum("remove", contributions, self.config)
        self.assertTrue(result.quorum_met)
        self.assertAlmostEqual(result.agreement_ratio, 4 / 5, places=5)

    def test_quorum_add_action_requires_endorse(self):
        contributions = (
            PeerContribution("nHVal1", 0.9, "endorse", "SIG1"),
            PeerContribution("nHVal2", 0.85, "endorse", "SIG2"),
            PeerContribution("nHVal3", 0.95, "endorse", "SIG3"),
        )
        result = evaluate_quorum("add", contributions, self.config)
        self.assertTrue(result.quorum_met)


class TestActionMapping(unittest.TestCase):
    def test_escalate_maps_to_remove(self):
        self.assertEqual(map_consensus_action_to_amendment("escalate"), "remove")

    def test_warn_maps_to_flag(self):
        self.assertEqual(map_consensus_action_to_amendment("warn"), "flag")

    def test_maintain_maps_to_add(self):
        self.assertEqual(map_consensus_action_to_amendment("maintain"), "add")

    def test_unknown_action_raises(self):
        with self.assertRaises(ValueError):
            map_consensus_action_to_amendment("unknown")


class TestBuildScoreSummary(unittest.TestCase):
    def test_computes_summary_from_contributions(self):
        contributions = (
            PeerContribution("nHVal1", 0.9, "endorse", "SIG1"),
            PeerContribution("nHVal2", 0.8, "endorse", "SIG2"),
            PeerContribution("nHVal3", -0.5, "flag", "SIG3"),
        )
        summary = build_score_summary(contributions)
        self.assertAlmostEqual(summary.avg_score, 0.4, places=2)
        self.assertEqual(summary.min_score, -0.5)
        self.assertEqual(summary.max_score, 0.9)
        self.assertEqual(summary.endorsements, 2)
        self.assertEqual(summary.flags, 1)
        self.assertEqual(summary.total_reporters, 3)


class TestLoadConsensusSummary(unittest.TestCase):
    def test_loads_consensus_entries_from_json(self):
        summary_json = {
            "consensus_entries": [
                {
                    "target_address": "nHTarget1",
                    "reporters": ["nHVal1", "nHVal2", "nHVal3"],
                    "scores": [0.9, 0.85, 0.95],
                    "avg_score": 0.9,
                    "min_score": 0.85,
                    "max_score": 0.95,
                    "endorsements": 3,
                    "flags": 0,
                    "recommended_action": "maintain",
                    "threshold_reason": "maintain",
                },
                {
                    "target_address": "nHTarget2",
                    "reporters": ["nHVal1", "nHVal2", "nHVal3"],
                    "scores": [-0.8, -0.9, -0.7],
                    "avg_score": -0.8,
                    "min_score": -0.9,
                    "max_score": -0.7,
                    "endorsements": 0,
                    "flags": 3,
                    "recommended_action": "escalate",
                    "threshold_reason": "escalate",
                },
            ],
            "generated_at": "2026-03-28T12:00:00Z",
        }
        entries = load_consensus_summary(summary_json)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["target_address"], "nHTarget1")
        self.assertEqual(entries[1]["recommended_action"], "escalate")


class TestBuildAmendmentProposals(unittest.TestCase):
    def test_generates_proposals_for_each_consensus_entry(self):
        entries = [
            {
                "target_address": "nHTargetBad",
                "reporters": ["nHVal1", "nHVal2", "nHVal3"],
                "scores": [-0.8, -0.9, -0.7],
                "avg_score": -0.8,
                "min_score": -0.9,
                "max_score": -0.7,
                "endorsements": 0,
                "flags": 3,
                "recommended_action": "escalate",
                "threshold_reason": "escalate",
            },
            {
                "target_address": "nHTargetGood",
                "reporters": ["nHVal1", "nHVal2", "nHVal3"],
                "scores": [0.9, 0.85, 0.95],
                "avg_score": 0.9,
                "min_score": 0.85,
                "max_score": 0.95,
                "endorsements": 3,
                "flags": 0,
                "recommended_action": "maintain",
                "threshold_reason": "maintain",
            },
        ]
        peer_signatures = {
            "nHVal1": "SIG_VAL1",
            "nHVal2": "SIG_VAL2",
            "nHVal3": "SIG_VAL3",
        }
        config = AmendmentConfig()
        proposals = build_amendment_proposals(entries, peer_signatures, config, proposing_validator="nHProposer")
        self.assertEqual(len(proposals), 2)

        remove_proposal = [p for p in proposals if p.amendment_action == "remove"][0]
        self.assertTrue(remove_proposal.quorum_met)
        self.assertEqual(remove_proposal.target_validator_public_key, "nHTargetBad")
        self.assertEqual(len(remove_proposal.contributing_peers), 3)
        self.assertEqual(remove_proposal.score_summary.flags, 3)

        add_proposal = [p for p in proposals if p.amendment_action == "add"][0]
        self.assertTrue(add_proposal.quorum_met)
        self.assertEqual(add_proposal.score_summary.endorsements, 3)

    def test_flag_proposal_quorum_not_met_with_minority_flags(self):
        entries = [
            {
                "target_address": "nHTargetSplit",
                "reporters": ["nHVal1", "nHVal2", "nHVal3"],
                "scores": [-0.8, 0.9, 0.9],
                "avg_score": 0.333,
                "min_score": -0.8,
                "max_score": 0.9,
                "endorsements": 2,
                "flags": 1,
                "recommended_action": "warn",
                "threshold_reason": "warn",
            },
        ]
        peer_signatures = {
            "nHVal1": "SIG_VAL1",
            "nHVal2": "SIG_VAL2",
            "nHVal3": "SIG_VAL3",
        }
        config = AmendmentConfig()
        proposals = build_amendment_proposals(entries, peer_signatures, config, proposing_validator="nHProposer")
        flag_proposal = [p for p in proposals if p.amendment_action == "flag"][0]
        self.assertFalse(flag_proposal.quorum_met)


class TestBuildAmendmentMemoPayload(unittest.TestCase):
    def test_builds_valid_payload_with_schema(self):
        contributions = (
            PeerContribution("nHVal1", -0.8, "jail", "SIG1"),
            PeerContribution("nHVal2", -0.9, "jail", "SIG2"),
            PeerContribution("nHVal3", -0.7, "jail", "SIG3"),
        )
        summary = ScoreSummary(-0.8, -0.9, -0.7, 0, 3, 3)
        proposal = AmendmentProposal(
            amendment_action="remove",
            target_validator_public_key="nHTargetBad",
            quorum_met=True,
            agreement_ratio=1.0,
            contributing_peers=contributions,
            score_summary=summary,
            proposed_at="2026-03-28T12:00:00Z",
            proposing_validator_public_key="nHProposer",
        )
        payload = build_amendment_memo_payload(proposal)
        self.assertEqual(payload["schema"], "postfiat.unl_amendment.v1")
        self.assertEqual(payload["amendment_action"], "remove")
        self.assertEqual(payload["target_validator_public_key"], "nHTargetBad")
        self.assertTrue(payload["quorum_met"])
        self.assertEqual(len(payload["contributing_peers"]), 3)
        self.assertIn("score_summary", payload)
        self.assertEqual(payload["score_summary"]["flags"], 3)


class TestSignAmendmentProposal(unittest.TestCase):
    def test_signs_proposal_and_builds_memo(self):
        signing_key = nacl.signing.SigningKey.generate()
        pub_key = addresscodec.encode_node_public_key(b"\xed" + bytes(signing_key.verify_key))

        contributions = (
            PeerContribution("nHVal1", -0.8, "jail", "SIG1"),
        )
        summary = ScoreSummary(-0.8, -0.8, -0.8, 0, 1, 1)
        proposal = AmendmentProposal(
            amendment_action="remove",
            target_validator_public_key="nHTarget",
            quorum_met=True,
            agreement_ratio=1.0,
            contributing_peers=contributions,
            score_summary=summary,
            proposed_at="2026-03-28T12:00:00Z",
            proposing_validator_public_key=pub_key,
        )
        signed = sign_amendment_proposal(proposal, signing_key)
        self.assertEqual(signed.proposal, proposal)
        self.assertIn("proposal_signature", signed.signed_payload)
        self.assertTrue(len(signed.proposal_signature) > 0)
        self.assertTrue(len(signed.memo_hex) > 0)


class TestSimulation(unittest.TestCase):
    def test_simulation_generates_3_validators_and_4_targets(self):
        sim = generate_simulation()
        self.assertEqual(len(sim["validators"]), 3)
        self.assertEqual(len(sim["consensus_entries"]), 4)
        self.assertEqual(len(sim["peer_signatures"]), 3)
        for v in sim["validators"]:
            self.assertTrue(len(v["validator_public_key"]) > 10)
            self.assertTrue(len(v["signature_hex"]) > 10)

    def test_simulation_pipeline_produces_signed_proposals(self):
        sim = generate_simulation()
        config = AmendmentConfig()
        proposals = build_amendment_proposals(
            sim["consensus_entries"],
            sim["peer_signatures"],
            config,
            proposing_validator=sim["validators"][0]["validator_public_key"],
        )
        self.assertGreaterEqual(len(proposals), 1)

        remove_proposals = [p for p in proposals if p.amendment_action == "remove"]
        self.assertGreaterEqual(len(remove_proposals), 1)
        self.assertTrue(remove_proposals[0].quorum_met)
        self.assertEqual(len(remove_proposals[0].contributing_peers), 3)

        signing_key = sim["validators_with_keys"][0]["signing_key"]
        signed = sign_amendment_proposal(remove_proposals[0], signing_key)
        self.assertTrue(len(signed.proposal_signature) > 0)
        self.assertEqual(signed.signed_payload["schema"], "postfiat.unl_amendment.v1")


class TestCLI(unittest.TestCase):
    def test_simulate_mode_outputs_all_sections(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = amendment_main(["--simulate"])
        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("[INGEST]", output)
        self.assertIn("[QUORUM]", output)
        self.assertIn("[PROPOSAL]", output)
        self.assertIn("[MEMO]", output)
        self.assertIn("action=remove", output)
        self.assertIn("quorum_met=True", output)
        self.assertIn("postfiat.unl_amendment.v1", output)

    def test_simulate_shows_at_least_one_remove_proposal(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = amendment_main(["--simulate"])
        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        remove_lines = [l for l in output.splitlines() if "action=remove" in l and "quorum_met=True" in l]
        self.assertGreaterEqual(len(remove_lines), 1)

    def test_simulate_json_out(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        try:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = amendment_main(["--simulate", "--json-out", json_path])
            self.assertEqual(exit_code, 0)
            data = json.loads(Path(json_path).read_text())
            self.assertIn("proposals", data)
            self.assertGreaterEqual(len(data["proposals"]), 1)
        finally:
            Path(json_path).unlink(missing_ok=True)


class TestDryRunTransaction(unittest.TestCase):
    def test_dry_run_builds_signed_accountset(self):
        sim = generate_simulation()
        config = AmendmentConfig()
        proposals = build_amendment_proposals(
            sim["consensus_entries"],
            sim["peer_signatures"],
            config,
            proposing_validator=sim["validators"][0]["validator_public_key"],
        )
        remove_proposal = [p for p in proposals if p.amendment_action == "remove" and p.quorum_met][0]
        signing_key = sim["validators_with_keys"][0]["signing_key"]
        signed = sign_amendment_proposal(remove_proposal, signing_key)

        fee_payer_wallet = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        fake_client = MagicMock()
        fake_client.request.side_effect = [
            MagicMock(result={"info": {"network_id": 21338, "validated_ledger": {"seq": 7654321}}}),
            Exception("Account does not exist"),
        ]
        from unl_voting import FeePayerContext
        wallet_ctx = FeePayerContext(wallet=fee_payer_wallet, source="test")
        from unl_voting import build_dry_run_transaction
        signed_tx, metadata, seq_src = build_dry_run_transaction(fake_client, wallet_ctx, signed.memo)

        self.assertEqual(signed_tx.account, fee_payer_wallet.address)
        self.assertEqual(len(signed_tx.memos), 1)
        self.assertTrue(signed_tx.is_signed())


if __name__ == "__main__":
    unittest.main()
