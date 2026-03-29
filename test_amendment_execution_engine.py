#!/usr/bin/env python3
"""
Unit tests for the amendment execution engine.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zlib
from pathlib import Path

from amendment_execution_engine import (
    DecodedAmendmentProposal,
    ExecutionConfig,
    ExecutionReceipt,
    ProposalGroup,
    SupermajorityResult,
    build_execution_receipt,
    build_proposal_id,
    build_receipt_memo,
    compute_validator_set_hash,
    decode_amendment_memo_payload,
    evaluate_supermajority,
    execute_amendment,
    extract_amendment_proposals_from_tx,
    group_proposals,
)
from unl_voting import encode_memo_field


AMENDMENT_SCHEMA = "postfiat.unl_amendment.v1"


def make_zlib_memo(payload: dict) -> dict:
    """Build a memo dict matching the format produced by sign_amendment_proposal."""
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    compressed = zlib.compress(payload_json.encode("utf-8"), level=9)
    return {
        "MemoData": compressed.hex().upper(),
        "MemoType": encode_memo_field(AMENDMENT_SCHEMA),
        "MemoFormat": encode_memo_field("application/json+zlib"),
    }


def make_proposal_payload(
    action: str = "remove",
    target: str = "nHTargetKey111",
    proposer: str = "nHProposer111",
) -> dict:
    return {
        "schema": AMENDMENT_SCHEMA,
        "amendment_action": action,
        "target_validator_public_key": target,
        "quorum_met": True,
        "agreement_ratio": 1.0,
        "contributing_peers": [
            {"validator_public_key": "nHPeer1", "score": -0.9, "status": "jail", "signature": "AABB"}
        ],
        "score_summary": {"avg_score": -0.9, "endorsements": 0, "flags": 1, "total_reporters": 1},
        "proposed_at": "2026-03-29T00:00:00Z",
        "proposing_validator_public_key": proposer,
        "proposal_signature": "DEADBEEF",
    }


def make_tx_entry(
    account: str,
    tx_hash: str,
    memos: list[dict],
    ledger_index: int = 100,
) -> dict:
    return {
        "tx": {
            "Account": account,
            "hash": tx_hash,
            "TransactionType": "AccountSet",
            "Memos": [{"Memo": m} for m in memos],
        },
        "ledger_index": ledger_index,
        "validated": True,
    }


class TestDecodeAmendmentMemoPayload(unittest.TestCase):
    def test_decode_zlib_compressed(self):
        payload = make_proposal_payload()
        memo = make_zlib_memo(payload)
        result = decode_amendment_memo_payload(memo)
        self.assertIsNotNone(result)
        self.assertEqual(result["amendment_action"], "remove")
        self.assertEqual(result["target_validator_public_key"], "nHTargetKey111")

    def test_returns_none_for_wrong_schema(self):
        memo = {
            "MemoData": encode_memo_field('{"key":"value"}'),
            "MemoType": encode_memo_field("postfiat.other.v1"),
            "MemoFormat": encode_memo_field("application/json"),
        }
        result = decode_amendment_memo_payload(memo)
        self.assertIsNone(result)

    def test_returns_none_for_missing_memo_type(self):
        memo = {"MemoData": "AABB"}
        result = decode_amendment_memo_payload(memo)
        self.assertIsNone(result)

    def test_returns_none_for_invalid_zlib(self):
        memo = {
            "MemoData": "DEADBEEF",
            "MemoType": encode_memo_field(AMENDMENT_SCHEMA),
            "MemoFormat": encode_memo_field("application/json+zlib"),
        }
        result = decode_amendment_memo_payload(memo)
        self.assertIsNone(result)

    def test_decode_plain_json(self):
        payload = make_proposal_payload()
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        memo = {
            "MemoData": encode_memo_field(payload_json),
            "MemoType": encode_memo_field(AMENDMENT_SCHEMA),
            "MemoFormat": encode_memo_field("application/json"),
        }
        result = decode_amendment_memo_payload(memo)
        self.assertIsNotNone(result)
        self.assertEqual(result["amendment_action"], "remove")

    def test_handles_lowercase_keys(self):
        payload = make_proposal_payload()
        memo_zlib = make_zlib_memo(payload)
        memo = {
            "memo_data": memo_zlib["MemoData"],
            "memo_type": memo_zlib["MemoType"],
            "memo_format": memo_zlib["MemoFormat"],
        }
        result = decode_amendment_memo_payload(memo)
        self.assertIsNotNone(result)


class TestExtractAmendmentProposals(unittest.TestCase):
    def test_extract_single_proposal(self):
        payload = make_proposal_payload()
        memo = make_zlib_memo(payload)
        entry = make_tx_entry("rAccount1", "HASH1", [memo])
        proposals = extract_amendment_proposals_from_tx(entry)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].tx_hash, "HASH1")
        self.assertEqual(proposals[0].account, "rAccount1")
        self.assertEqual(proposals[0].amendment_action, "remove")
        self.assertEqual(proposals[0].ledger_index, 100)

    def test_skip_non_amendment_memos(self):
        other_memo = {
            "MemoData": encode_memo_field('{"key":"value"}'),
            "MemoType": encode_memo_field("postfiat.other.v1"),
        }
        entry = make_tx_entry("rAccount1", "HASH2", [other_memo])
        proposals = extract_amendment_proposals_from_tx(entry)
        self.assertEqual(len(proposals), 0)

    def test_tx_json_container(self):
        payload = make_proposal_payload()
        memo = make_zlib_memo(payload)
        entry = {
            "tx_json": {
                "Account": "rAccount2",
                "hash": "HASH3",
                "Memos": [{"Memo": memo}],
            },
            "ledger_index": 200,
        }
        proposals = extract_amendment_proposals_from_tx(entry)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].account, "rAccount2")

    def test_skip_missing_action(self):
        payload = make_proposal_payload()
        del payload["amendment_action"]
        memo = make_zlib_memo(payload)
        entry = make_tx_entry("rAccount1", "HASH4", [memo])
        proposals = extract_amendment_proposals_from_tx(entry)
        self.assertEqual(len(proposals), 0)


class TestGroupProposals(unittest.TestCase):
    def _make_decoded(self, account: str, target: str, action: str) -> DecodedAmendmentProposal:
        return DecodedAmendmentProposal(
            tx_hash=f"HASH_{account}_{target}",
            account=account,
            ledger_index=100,
            amendment_action=action,
            target_validator_public_key=target,
            quorum_met=True,
            agreement_ratio=1.0,
            contributing_peers=(),
            score_summary={},
            proposed_at="2026-03-29T00:00:00Z",
            proposing_validator_public_key="nHProposer",
            raw_payload={},
        )

    def test_group_by_target_and_action(self):
        proposals = [
            self._make_decoded("rA", "nHTarget1", "remove"),
            self._make_decoded("rB", "nHTarget1", "remove"),
            self._make_decoded("rC", "nHTarget2", "add"),
        ]
        groups = group_proposals(proposals)
        self.assertEqual(len(groups), 2)

        remove_groups = [g for g in groups if g.amendment_action == "remove"]
        add_groups = [g for g in groups if g.amendment_action == "add"]
        self.assertEqual(len(remove_groups), 1)
        self.assertEqual(len(add_groups), 1)
        self.assertEqual(len(remove_groups[0].unique_endorsing_accounts), 2)
        self.assertIn("rA", remove_groups[0].unique_endorsing_accounts)
        self.assertIn("rB", remove_groups[0].unique_endorsing_accounts)

    def test_dedup_same_account(self):
        proposals = [
            self._make_decoded("rA", "nHTarget1", "remove"),
            self._make_decoded("rA", "nHTarget1", "remove"),
        ]
        groups = group_proposals(proposals)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].unique_endorsing_accounts), 1)


class TestEvaluateSupermajority(unittest.TestCase):
    def _make_group(self, endorsers: int) -> ProposalGroup:
        accounts = tuple(f"rAccount{i}" for i in range(endorsers))
        return ProposalGroup(
            target_validator_public_key="nHTarget1",
            amendment_action="remove",
            proposals=(),
            unique_endorsing_accounts=accounts,
        )

    def test_pass_at_100_percent(self):
        group = self._make_group(3)
        result = evaluate_supermajority(group, 3, 0.8)
        self.assertTrue(result.passed)
        self.assertEqual(result.endorsement_count, 3)
        self.assertAlmostEqual(result.endorsement_ratio, 1.0)

    def test_fail_at_33_percent(self):
        group = self._make_group(1)
        result = evaluate_supermajority(group, 3, 0.8)
        self.assertFalse(result.passed)
        self.assertEqual(result.endorsement_count, 1)

    def test_boundary_exactly_80_percent(self):
        # 80% is NOT strictly greater than 0.8, so should fail
        group = self._make_group(4)
        result = evaluate_supermajority(group, 5, 0.8)
        self.assertFalse(result.passed)

    def test_pass_above_80_percent(self):
        group = self._make_group(5)
        result = evaluate_supermajority(group, 5, 0.8)
        self.assertTrue(result.passed)

    def test_zero_validators(self):
        group = self._make_group(0)
        result = evaluate_supermajority(group, 0, 0.8)
        self.assertFalse(result.passed)


class TestComputeValidatorSetHash(unittest.TestCase):
    def test_deterministic(self):
        keys = ("nHB", "nHA", "nHC")
        h1 = compute_validator_set_hash(keys)
        h2 = compute_validator_set_hash(keys)
        self.assertEqual(h1, h2)

    def test_order_independent(self):
        h1 = compute_validator_set_hash(("nHB", "nHA"))
        h2 = compute_validator_set_hash(("nHA", "nHB"))
        self.assertEqual(h1, h2)

    def test_different_keys_different_hash(self):
        h1 = compute_validator_set_hash(("nHA",))
        h2 = compute_validator_set_hash(("nHB",))
        self.assertNotEqual(h1, h2)


class TestExecuteAmendment(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.cfg_path = Path(self.tmp_dir) / "rippled.cfg"
        self.alert_log = Path(self.tmp_dir) / "alerts.jsonl"
        self.cfg_path.write_text(
            "[server]\nport_rpc_admin_local\n\n"
            "[validators]\n"
            "nHTargetToRemove111111111111111111111111\n"
            "nHHealthyValidator222222222222222222222222\n"
        )

    def _make_config(self) -> ExecutionConfig:
        return ExecutionConfig(
            supermajority_threshold=0.8,
            known_proposer_count=3,
            poll_accounts=("rA", "rB", "rC"),
            proposal_window_seconds=600,
            xrpl_rpc_url="http://localhost:5005",
            rippled_cfg_path=self.cfg_path,
            trusted_validators_section="validators",
            reload_command=("true",),
            alert_log_path=self.alert_log,
        )

    def _make_sm_result(self, action: str, target: str, passed: bool) -> SupermajorityResult:
        group = ProposalGroup(
            target_validator_public_key=target,
            amendment_action=action,
            proposals=(),
            unique_endorsing_accounts=("rA", "rB", "rC"),
        )
        return SupermajorityResult(
            group=group,
            endorsement_count=3,
            known_validator_count=3,
            endorsement_ratio=1.0,
            passed=passed,
        )

    def test_remove_on_pass(self):
        config = self._make_config()
        result = self._make_sm_result("remove", "nHTargetToRemove111111111111111111111111", True)
        changed, diff, vhash = execute_amendment(result, config)
        self.assertTrue(changed)
        self.assertIn("-nHTargetToRemove111111111111111111111111", diff)
        updated_text = self.cfg_path.read_text()
        self.assertNotIn("nHTargetToRemove111111111111111111111111", updated_text)
        self.assertIn("nHHealthyValidator222222222222222222222222", updated_text)

    def test_add_on_pass(self):
        config = self._make_config()
        result = self._make_sm_result("add", "nHNewValidator333333333333333333333333333", True)
        changed, diff, vhash = execute_amendment(result, config)
        self.assertTrue(changed)
        self.assertIn("+nHNewValidator333333333333333333333333333", diff)
        updated_text = self.cfg_path.read_text()
        self.assertIn("nHNewValidator333333333333333333333333333", updated_text)

    def test_flag_no_config_change(self):
        config = self._make_config()
        result = self._make_sm_result("flag", "nHTargetToRemove111111111111111111111111", True)
        changed, diff, vhash = execute_amendment(result, config)
        self.assertFalse(changed)
        self.assertEqual(diff, "")
        self.assertTrue(self.alert_log.exists())

    def test_no_change_on_fail(self):
        config = self._make_config()
        result = self._make_sm_result("remove", "nHTargetToRemove111111111111111111111111", False)
        changed, diff, vhash = execute_amendment(result, config)
        self.assertFalse(changed)
        updated_text = self.cfg_path.read_text()
        self.assertIn("nHTargetToRemove111111111111111111111111", updated_text)


class TestBuildExecutionReceipt(unittest.TestCase):
    def test_pass_receipt(self):
        group = ProposalGroup(
            target_validator_public_key="nHTarget1",
            amendment_action="remove",
            proposals=(),
            unique_endorsing_accounts=("rA", "rB", "rC"),
        )
        sm_result = SupermajorityResult(
            group=group,
            endorsement_count=3,
            known_validator_count=3,
            endorsement_ratio=1.0,
            passed=True,
        )
        receipt = build_execution_receipt(sm_result, True, "abc123hash")
        self.assertEqual(receipt.result, "PASS")
        self.assertEqual(receipt.amendment_action, "remove")
        self.assertEqual(receipt.resulting_validator_set_hash, "abc123hash")
        self.assertTrue(len(receipt.proposal_id) == 64)

    def test_fail_receipt(self):
        group = ProposalGroup(
            target_validator_public_key="nHTarget2",
            amendment_action="remove",
            proposals=(),
            unique_endorsing_accounts=("rA",),
        )
        sm_result = SupermajorityResult(
            group=group,
            endorsement_count=1,
            known_validator_count=3,
            endorsement_ratio=0.333333,
            passed=False,
        )
        receipt = build_execution_receipt(sm_result, False, "def456hash")
        self.assertEqual(receipt.result, "FAIL")


class TestBuildReceiptMemo(unittest.TestCase):
    def test_memo_structure(self):
        receipt = ExecutionReceipt(
            proposal_id="abc123",
            amendment_action="remove",
            target_validator_public_key="nHTarget1",
            result="PASS",
            resulting_validator_set_hash="hash123",
            executed_at="2026-03-29T00:00:00Z",
            endorsement_count=3,
            endorsement_ratio=1.0,
        )
        memo = build_receipt_memo(receipt)
        self.assertIsNotNone(memo.memo_data)
        self.assertIsNotNone(memo.memo_type)
        self.assertIsNotNone(memo.memo_format)

        memo_type = bytes.fromhex(memo.memo_type).decode("utf-8")
        self.assertEqual(memo_type, "postfiat.unl_amendment_receipt.v1")

        memo_data = bytes.fromhex(memo.memo_data).decode("utf-8")
        payload = json.loads(memo_data)
        self.assertEqual(payload["result"], "PASS")
        self.assertEqual(payload["proposal_id"], "abc123")


class TestBuildProposalId(unittest.TestCase):
    def test_deterministic(self):
        id1 = build_proposal_id("nHTarget1", "remove", ("rA", "rB"))
        id2 = build_proposal_id("nHTarget1", "remove", ("rA", "rB"))
        self.assertEqual(id1, id2)

    def test_order_independent_accounts(self):
        id1 = build_proposal_id("nHTarget1", "remove", ("rB", "rA"))
        id2 = build_proposal_id("nHTarget1", "remove", ("rA", "rB"))
        self.assertEqual(id1, id2)

    def test_different_targets(self):
        id1 = build_proposal_id("nHTarget1", "remove", ("rA",))
        id2 = build_proposal_id("nHTarget2", "remove", ("rA",))
        self.assertNotEqual(id1, id2)


if __name__ == "__main__":
    unittest.main()
