"""
AegisFlow AI — Cryptographic Tamper-Proof Audit Ledger (PCI-DSS 10.x & Zero-Trust Audit Engine)
Author: Om Kamble

Implements a SHA-256 cryptographically hash-chained immutable audit ledger (Merkle chain)
for non-repudiation of financial risk decisions.
"""

import os
import json
import time
import hmac
import hashlib
from typing import Dict, Any, List, Optional, Tuple


class AuditBlock:
    def __init__(
        self,
        index: int,
        timestamp: float,
        txn_id: str,
        user_id: str,
        amount: float,
        decision: str,
        risk_score: float,
        triggered_rules: List[str],
        prev_hash: str,
        block_hash: Optional[str] = None,
        signature: Optional[str] = None
    ):
        self.index = index
        self.timestamp = timestamp
        self.txn_id = txn_id
        self.user_id = user_id
        self.amount = round(amount, 2)
        self.decision = decision
        self.risk_score = round(risk_score, 4)
        self.triggered_rules = triggered_rules or []
        self.prev_hash = prev_hash
        self.block_hash = block_hash or self.compute_hash()
        self.signature = signature or self.compute_signature()

    def get_canonical_payload(self) -> str:
        """Returns deterministic JSON string for hashing."""
        payload = {
            "index": self.index,
            "timestamp": round(self.timestamp, 4),
            "txn_id": self.txn_id,
            "user_id": self.user_id,
            "amount": self.amount,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "triggered_rules": sorted(self.triggered_rules),
            "prev_hash": self.prev_hash
        }
        return json.dumps(payload, sort_keys=True, separators=(',', ':'))

    def compute_hash(self) -> str:
        canonical = self.get_canonical_payload()
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def compute_signature(self, secret_key: str = "AEGISFLOW_AUDIT_SECRET_2026") -> str:
        return hmac.new(
            secret_key.encode('utf-8'),
            self.block_hash.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            "txn_id": self.txn_id,
            "user_id": self.user_id,
            "amount": self.amount,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "triggered_rules": self.triggered_rules,
            "prev_hash": self.prev_hash,
            "block_hash": self.block_hash,
            "signature": self.signature
        }


class CryptographicAuditLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self, secret_key: str = "AEGISFLOW_AUDIT_SECRET_2026"):
        self.secret_key = secret_key
        self.chain: List[AuditBlock] = []
        self._is_tampered = False
        self._tampered_block_index: Optional[int] = None

        # Create Genesis Block
        genesis = AuditBlock(
            index=0,
            timestamp=time.time(),
            txn_id="TXN_GENESIS_ROOT",
            user_id="SYSTEM_ROOT",
            amount=0.0,
            decision="SYSTEM_INITIALIZATION",
            risk_score=0.0,
            triggered_rules=["GENESIS_INITIALIZATION"],
            prev_hash=self.GENESIS_HASH
        )
        self.chain.append(genesis)

    def record_decision(
        self,
        txn_id: str,
        user_id: str,
        amount: float,
        decision: str,
        risk_score: float,
        triggered_rules: List[str],
        timestamp: Optional[float] = None
    ) -> Dict[str, Any]:
        """Cryptographically signs and appends a risk decision block to the ledger."""
        now = timestamp or time.time()
        prev_block = self.chain[-1]
        prev_hash = prev_block.block_hash

        new_index = len(self.chain)
        block = AuditBlock(
            index=new_index,
            timestamp=now,
            txn_id=txn_id,
            user_id=user_id,
            amount=amount,
            decision=decision,
            risk_score=risk_score,
            triggered_rules=triggered_rules,
            prev_hash=prev_hash
        )
        self.chain.append(block)

        # Cap memory chain at 1000 blocks for performance
        if len(self.chain) > 1000:
            self.chain = [self.chain[0]] + self.chain[-999:]

        return block.to_dict()

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Performs a full cryptographic validation of the entire hash chain.
        Detects broken links, altered payloads, and forged signatures.
        """
        start_time = time.perf_counter()
        
        if not self.chain:
            return {
                "is_valid": False,
                "status": "EMPTY_CHAIN",
                "blocks_verified": 0,
                "error": "Audit ledger contains no blocks."
            }

        # Verify Genesis
        if self.chain[0].prev_hash != self.GENESIS_HASH:
            return {
                "is_valid": False,
                "status": "COMPROMISED",
                "error_at_index": 0,
                "reason": "Genesis block prev_hash is forged or invalid."
            }

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Verify link continuity
            if current.prev_hash != prev.block_hash:
                return {
                    "is_valid": False,
                    "status": "COMPROMISED_CHAIN_LINK",
                    "error_at_index": i,
                    "reason": f"Broken cryptographic link at Block #{i}. Expected prev_hash {prev.block_hash[:12]}... but got {current.prev_hash[:12]}...",
                    "block": current.to_dict()
                }

            # 2. Verify payload hash integrity
            recalculated_hash = current.compute_hash()
            if current.block_hash != recalculated_hash:
                return {
                    "is_valid": False,
                    "status": "TAMPERED_BLOCK_PAYLOAD",
                    "error_at_index": i,
                    "reason": f"Block #{i} payload was modified! Recalculated SHA-256 does not match stored block_hash.",
                    "stored_hash": current.block_hash,
                    "recalculated_hash": recalculated_hash,
                    "tampered_block": current.to_dict()
                }

            # 3. Verify HMAC signature
            recalculated_sig = current.compute_signature(self.secret_key)
            if current.signature != recalculated_sig:
                return {
                    "is_valid": False,
                    "status": "INVALID_SIGNATURE",
                    "error_at_index": i,
                    "reason": f"Block #{i} signature verification failed (Cryptographic Forgery detected)."
                }

        verification_latency = round((time.perf_counter() - start_time) * 1000, 3)
        return {
            "is_valid": True,
            "status": "VERIFIED_SECURE",
            "blocks_verified": len(self.chain),
            "latest_block_index": len(self.chain) - 1,
            "latest_block_hash": self.chain[-1].block_hash,
            "root_merkle_digest": self.get_root_digest(),
            "verification_latency_ms": verification_latency,
            "compliance": "PCI-DSS 10.x & Zero-Trust Immutable Standards Met"
        }

    def get_root_digest(self) -> str:
        """Returns Merkle-style root digest of the entire current chain."""
        if not self.chain:
            return self.GENESIS_HASH
        hasher = hashlib.sha256()
        for block in self.chain:
            hasher.update(block.block_hash.encode('utf-8'))
        return hasher.hexdigest()

    def get_recent_blocks(self, limit: int = 15) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in reversed(self.chain[-limit:])]

    def simulate_tampering(self, block_index: Optional[int] = None) -> Dict[str, Any]:
        """
        Interactive demonstration feature for interviews & audits:
        Maliciously alters a historical block in memory to prove how the SHA-256 chain detects it.
        """
        if len(self.chain) <= 1:
            # Need at least one non-genesis block
            self.record_decision(
                txn_id="TXN_DEMO_SAMPLE",
                user_id="usr_demo",
                amount=1500.0,
                decision="BLOCK",
                risk_score=0.92,
                triggered_rules=["RULE_ANOMALY_V14"]
            )

        target_idx = block_index if (block_index is not None and block_index < len(self.chain)) else (len(self.chain) - 1)
        if target_idx == 0:
            target_idx = 1 if len(self.chain) > 1 else 0

        target_block = self.chain[target_idx]
        original_decision = target_block.decision
        original_score = target_block.risk_score

        # Malicious insider changes BLOCK to APPROVE
        target_block.decision = "APPROVE" if original_decision == "BLOCK" else "BLOCK"
        target_block.risk_score = 0.05 if original_decision == "BLOCK" else 0.99

        self._is_tampered = True
        self._tampered_block_index = target_idx

        return {
            "message": "Malicious tampering simulated successfully.",
            "tampered_block_index": target_idx,
            "original_decision": original_decision,
            "tampered_decision": target_block.decision,
            "warning": "The ledger is now in a COMPROMISED state. Run verification to observe instant detection."
        }

    def restore_and_reseal(self) -> Dict[str, Any]:
        """Recalculates all hashes to re-seal and restore ledger health."""
        for i in range(1, len(self.chain)):
            self.chain[i].prev_hash = self.chain[i - 1].block_hash
            self.chain[i].block_hash = self.chain[i].compute_hash()
            self.chain[i].signature = self.chain[i].compute_signature(self.secret_key)

        self._is_tampered = False
        self._tampered_block_index = None
        return {
            "message": "Ledger restored and cryptographically re-sealed.",
            "status": "VERIFIED_SECURE",
            "total_blocks": len(self.chain),
            "new_root_digest": self.get_root_digest()
        }


# Global singleton instance
audit_ledger = CryptographicAuditLedger()

