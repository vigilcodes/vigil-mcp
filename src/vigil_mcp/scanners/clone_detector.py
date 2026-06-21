"""Token clone detector — flag copy-paste scam tokens by bytecode fingerprint.

Scam operators mass-deploy the same contract dozens of times with different
names. This scanner fingerprints a token's runtime bytecode and checks whether
that exact fingerprint has been seen at other addresses on the same chain.

Design (self-accumulating, keyless):
- Every scan hashes the token's normalized bytecode and records
  (fingerprint -> address) in a local SQLite DB.
- If a fingerprint already maps to other addresses, those are "clones".
- Cross-reference clones against the community scam DB: if any sibling is a
  reported scam, escalate the risk.

Fail-safe: sharing bytecode is NOT proof of a scam — legitimate tokens reuse
the same OpenZeppelin/template bytecode all the time. So a clone cluster alone
is "suspicious", never "dangerous"; risk only escalates when a sibling is an
actual reported scam. Missing data returns `unknown`, never `safe`.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from contextlib import closing
from typing import Optional

import httpx
from pydantic import BaseModel

from vigil_mcp.scanners.scam_db import ScamDatabase

DEFAULT_DB_PATH = os.getenv("VIGIL_CLONE_DB", os.path.join(os.path.expanduser("~"), ".vigil", "clone_fingerprints.db"))

# A clone cluster of this many addresses (incl. the queried one) or more is
# worth surfacing prominently.
_CLUSTER_FLAG_THRESHOLD = 3

# Minimum bytecode size to fingerprint. Tiny contracts (proxies, shells) share
# bytecode by design and would create noisy false clusters.
_MIN_CODE_BYTES = 200


class CloneResult(BaseModel):
    token: str
    chain: str
    available: bool = True
    determined: bool
    risk: str  # safe | suspicious | dangerous | unknown
    fingerprint: Optional[str] = None
    code_size_bytes: int = 0
    clone_count: int = 0  # other addresses sharing this fingerprint
    clones: list[str] = []
    scam_siblings: list[str] = []  # clones that are reported scams
    notes: list[str] = []


class CloneFingerprintStore:
    """Local SQLite store mapping bytecode fingerprint -> addresses seen."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS fingerprints (
                    fingerprint TEXT NOT NULL,
                    chain       TEXT NOT NULL,
                    address     TEXT NOT NULL,
                    first_seen  INTEGER NOT NULL,
                    PRIMARY KEY (chain, address)
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_fp ON fingerprints(fingerprint, chain)")

    def record(self, fingerprint: str, chain: str, address: str) -> None:
        """Record that `address` on `chain` has this fingerprint. Idempotent."""
        try:
            with closing(sqlite3.connect(self.db_path)) as c, c:
                c.execute(
                    "INSERT OR IGNORE INTO fingerprints (fingerprint, chain, address, first_seen) VALUES (?, ?, ?, ?)",
                    (fingerprint, chain.lower(), address.lower(), int(time.time())),
                )
        except Exception:  # noqa: BLE001 — fingerprint logging must never break a scan
            pass

    def siblings(self, fingerprint: str, chain: str, exclude: str) -> list[str]:
        """Return other addresses on `chain` sharing this fingerprint."""
        with closing(sqlite3.connect(self.db_path)) as c:
            rows = c.execute(
                "SELECT address FROM fingerprints WHERE fingerprint = ? AND chain = ? AND address != ? "
                "ORDER BY first_seen LIMIT 50",
                (fingerprint, chain.lower(), exclude.lower()),
            ).fetchall()
        return [r[0] for r in rows]


class CloneDetector:
    """Detect copy-paste clone tokens via bytecode fingerprinting."""

    def __init__(self, store: Optional[CloneFingerprintStore] = None) -> None:
        self.store = store or CloneFingerprintStore()
        self.scam_db = ScamDatabase()
        self.rpc_urls = {
            "base": os.getenv("BASE_RPC", "https://base.publicnode.com"),
            "ethereum": os.getenv("ETH_RPC", "https://eth.llamarpc.com"),
            "polygon": os.getenv("POLYGON_RPC", "https://polygon-rpc.com"),
            "arbitrum": os.getenv("ARBITRUM_RPC", "https://arb1.arbitrum.io/rpc"),
        }

    @staticmethod
    def _normalize_bytecode(code_hex: str) -> Optional[str]:
        """Strip the trailing CBOR metadata (Solidity appends a hash that differs
        per-compile) so functionally-identical contracts fingerprint the same.

        Returns hex without 0x, or None if the code is too small to fingerprint.
        """
        if not isinstance(code_hex, str):
            return None
        clean = code_hex[2:] if code_hex.startswith("0x") else code_hex
        if len(clean) < _MIN_CODE_BYTES * 2:
            return None
        # Solidity metadata: last 2 bytes (4 hex chars) encode the CBOR length.
        # Strip that CBOR blob so per-compile metadata doesn't change the hash.
        try:
            meta_len = int(clean[-4:], 16)  # length in bytes of the CBOR section
            cutoff = len(clean) - 4 - (meta_len * 2)
            if 0 < cutoff < len(clean):
                clean = clean[:cutoff]
        except ValueError:
            pass  # no parseable metadata length — fingerprint the whole code
        return clean

    @staticmethod
    def _fingerprint(normalized_hex: str) -> str:
        return hashlib.sha256(bytes.fromhex(normalized_hex)).hexdigest()

    async def detect(self, token: str, chain: str) -> CloneResult:
        token_l = token.lower()
        chain_l = chain.lower()
        rpc_url = self.rpc_urls.get(chain_l)

        if not rpc_url:
            return CloneResult(
                token=token_l,
                chain=chain_l,
                available=False,
                determined=False,
                risk="unknown",
                notes=[f"UNDETERMINED: no RPC configured for chain '{chain_l}'. Not a safety guarantee."],
            )

        # Fetch bytecode
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    rpc_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [token_l, "latest"]},
                )
                resp.raise_for_status()
                code = resp.json().get("result", "0x")
        except Exception as e:  # noqa: BLE001
            return CloneResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                risk="unknown",
                notes=[f"UNDETERMINED: bytecode fetch failed ({str(e)[:60]}). Not a safety guarantee."],
            )

        if code in ("0x", "0x0", ""):
            return CloneResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                risk="unknown",
                notes=["UNDETERMINED: no contract code at this address (EOA or self-destructed)."],
            )

        normalized = self._normalize_bytecode(code)
        code_size = (len(code) - 2) // 2 if code.startswith("0x") else len(code) // 2
        if normalized is None:
            return CloneResult(
                token=token_l,
                chain=chain_l,
                determined=False,
                risk="unknown",
                code_size_bytes=code_size,
                notes=[
                    "UNDETERMINED: contract too small to fingerprint reliably "
                    f"({code_size} bytes — likely a proxy or minimal shell)."
                ],
            )

        fingerprint = self._fingerprint(normalized)

        # Find siblings BEFORE recording this address (so we don't match self).
        siblings = self.store.siblings(fingerprint, chain_l, exclude=token_l)
        self.store.record(fingerprint, chain_l, token_l)

        # Cross-reference siblings against the community scam DB.
        scam_siblings: list[str] = []
        for sib in siblings:
            try:
                if self.scam_db.check(sib, chain_l).get("reported"):
                    scam_siblings.append(sib)
            except Exception:  # noqa: BLE001
                continue

        clone_count = len(siblings)
        risk, notes = self._assess(clone_count, scam_siblings)

        return CloneResult(
            token=token_l,
            chain=chain_l,
            determined=True,
            risk=risk,
            fingerprint=fingerprint,
            code_size_bytes=code_size,
            clone_count=clone_count,
            clones=siblings[:20],
            scam_siblings=scam_siblings,
            notes=notes,
        )

    def _assess(self, clone_count: int, scam_siblings: list[str]) -> tuple[str, list[str]]:
        notes: list[str] = []

        # A sibling that is a confirmed scam is the strongest signal.
        if scam_siblings:
            notes.append(
                f"DANGEROUS: identical bytecode to {len(scam_siblings)} address(es) "
                "reported as scams. This is a likely copy-paste scam clone."
            )
            return "dangerous", notes

        if clone_count >= _CLUSTER_FLAG_THRESHOLD:
            notes.append(
                f"SUSPICIOUS: identical bytecode found at {clone_count} other address(es) — "
                "possible mass-deployed clone cluster. Verify this is a known template "
                "(e.g. a standard token factory) and not a scam farm."
            )
            return "suspicious", notes

        if clone_count >= 1:
            notes.append(
                f"NOTE: identical bytecode seen at {clone_count} other address(es). "
                "Common for tokens built from the same factory/template; not a risk by itself."
            )
            return "safe", notes

        notes.append(
            "No clones seen yet — this bytecode fingerprint is new to VIGIL. "
            "Absence of clones is not a safety guarantee."
        )
        return "safe", notes
