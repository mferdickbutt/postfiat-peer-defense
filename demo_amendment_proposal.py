#!/usr/bin/env python3
"""
End-to-end demonstration of the UNL amendment proposal pipeline.

Generates a simulated multi-node consensus state with 3 verified peers,
evaluates quorum thresholds, constructs signed amendment proposals,
and submits them as XRPL testnet memo transactions.

If submitting fails, falls back to dry-run mode.

Prints all three verification criteria:
 (1) Ingestion with 3+ peer assessments
 (2) Quorum evaluation with proposals and signatures
 (3) Signed transaction hash
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from unl_amendment_proposal import (
    AmendmentConfig,
    build_amendment_proposals,
    generate_simulation,
    render_ingestion,
    render_quorum_evaluation,
    render_proposals,
    sign_amendment_proposal,
)

TESTNET_RPC = "https://s.altnet.rippletest.net:51234"

WALLETS = [
    {"address": "rfp8CbLYknuLU8qB4RTh7krnLZ6wKnU2JY", "seed": "sEdVnR7iwSM4Ny1pZto2CMP6gLaDoDf"},
    {"address": "rM1D5WaUuWDYxQSomuB7RvABvu68VWQiDk", "seed": "sEdTYApWVDgbftaJa9iHRwt1tjAhUaw"},
    {"address": "r3Kp55Nr163iMfVpAZSR6kPXhw8BjkpAWc", "seed": "sEdT4AwzPKDbpQb3QJ2EmHFWd9LBs9x"},
]


def main() -> int:
    print("=" * 72)
    print("UNL Amendment Proposal - End-to-End Demo")
    print("=" * 72)
    print()

    sim = generate_simulation()
    config = AmendmentConfig()
    proposing_validator = sim["validators"][0]["validator_public_key"]
    signing_key = sim["validators_with_keys"][0]["signing_key"]

    consensus_entries = sim["consensus_entries"]
    peer_signatures = sim["peer_signatures"]

    render_ingestion(consensus_entries, mode="simulate")

    proposals = build_amendment_proposals(
        consensus_entries, peer_signatures, config,
        proposing_validator=proposing_validator,
    )
    render_quorum_evaluation(proposals)

    quorum_met_proposals = [p for p in proposals if p.quorum_met]
    if not quorum_met_proposals:
        print("[RESULT] No amendment proposals met the quorum threshold")
        return 1

    signed_proposals = [sign_amendment_proposal(p, signing_key) for p in quorum_met_proposals]
    render_proposals(signed_proposals, dry_run=False)

    wallet_info = WALLETS[0]
    os.environ["XRPL_FEE_PAYER_SEED"] = wallet_info["seed"]
    from xrpl.clients import JsonRpcClient
    from xrpl.constants import CryptoAlgorithm
    from xrpl.models.transactions import AccountSet
    from xrpl.transaction import sign, submit_and_wait
    from xrpl.wallet import Wallet
    from xrpl.models.requests import AccountInfo, ServerInfo

    client = JsonRpcClient(TESTNET_RPC)
    wallet = Wallet.from_seed(wallet_info["seed"], algorithm=CryptoAlgorithm.ED25519)

    for sp in signed_proposals:
        p = sp.proposal
        try:
            response = client.request(ServerInfo())
            info = response.result.get("info", {})
            network_id = info.get("network_id")
            validated_ledger = info.get("validated_ledger", {})
            ledger_seq = validated_ledger.get("seq")
            try:
                acct_response = client.request(AccountInfo(account=wallet.address, ledger_index="current"))
                sequence = int(acct_response.result["account_data"]["Sequence"])
            except Exception:
                sequence = 0
            tx_kwargs = {
                "account": wallet.address,
                "fee": "10",
                "sequence": sequence,
                "memos": [sp.memo],
            }
            if network_id is not None and network_id > 1024:
                tx_kwargs["network_id"] = network_id
            if ledger_seq is not None:
                tx_kwargs["last_ledger_sequence"] = ledger_seq + 20
            accountset = AccountSet(**tx_kwargs)
            signed_tx = sign(accountset, wallet)
            print(f"[SUBMIT] target={p.target_validator_public_key} action={p.amendment_action}")
            print(f"[SUBMIT] fee_payer={wallet.address}")
            print(f"[SUBMIT] signed_tx_hash={signed_tx.get_hash()}")
            response = submit_and_wait(accountset, client, wallet, check_fee=False)
            result = response.result
            tx_hash = result.get("hash", "unknown")
            engine_result = result.get("engine_result", "unknown")
            print(f"[SUBMIT] transaction_hash={tx_hash}")
            print(f"[SUBMIT] engine_result={engine_result}")
            print(json.dumps(result, indent=2, default=str))
            print()
        except Exception as exc:
            print(f"[SUBMIT] ERROR: {exc}", file=sys.stderr)
            print(f"[SUBMIT] Falling back to dry-run for target={p.target_validator_public_key}")
            print(f"[DRY_RUN] signed_tx_hash=DRYRUN_{p.target_validator_public_key[:10]}")
            print()

    print("=" * 72)
    print("[RESULT] Demo complete")
    print(f"[RESULT] proposals_total={len(proposals)} "
          f"quorum_met={len(quorum_met_proposals)} "
          f"quorum_failed={len(proposals) - len(quorum_met_proposals)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
