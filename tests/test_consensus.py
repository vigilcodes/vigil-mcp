"""Tests for the multi-source consensus engine — the false-positive guard.

These lock in the core promise: a single source flagging risk can never push
the verdict past "medium"; risk only escalates to high/critical when multiple
independent sources agree.
"""

from vigil_mcp.scanners.consensus import (
    RISK,
    SAFE,
    UNKNOWN,
    ConsensusEngine,
    SourceVote,
)

TOKEN = "0x1111111111111111111111111111111111111111"


def _tally(votes):
    return ConsensusEngine()._tally(TOKEN, "base", votes)


def _safe(src, w=1.0):
    return SourceVote(source=src, vote=SAFE, weight=w)


def _risk(src, w=1.0, reasons=None):
    return SourceVote(source=src, vote=RISK, weight=w, reasons=reasons or [])


def _unknown(src):
    return SourceVote(source=src, vote=UNKNOWN, weight=0.0)


class TestConsensusTally:
    def test_all_safe_is_safe(self):
        r = _tally([_safe(s) for s in "abcde"])
        assert r.verdict == "safe"
        assert r.risk_sources == 0
        assert r.confidence == 1.0

    def test_single_strong_risk_capped_at_medium(self):
        # The false-positive guard: one loud source must NOT reach critical.
        votes = [_risk("goplus", 1.0, ["honeypot"])] + [_safe(s) for s in "bcde"]
        r = _tally(votes)
        assert r.verdict == "medium"
        assert r.risk_sources == 1

    def test_single_weak_risk_is_low(self):
        votes = [_risk("deployer", 0.5)] + [_safe(s) for s in "bcd"]
        r = _tally(votes)
        assert r.verdict == "low"

    def test_two_sources_agree_is_high(self):
        votes = [_risk("goplus"), _risk("scam_db")] + [_safe(s) for s in "cde"]
        r = _tally(votes)
        assert r.verdict == "high"
        assert r.risk_sources == 2

    def test_three_sources_agree_is_critical(self):
        votes = [_risk("goplus"), _risk("scam_db"), _risk("onchain", 0.8)] + [_safe(s) for s in "de"]
        r = _tally(votes)
        assert r.verdict == "critical"
        assert r.risk_sources == 3

    def test_all_unknown_is_unknown(self):
        r = _tally([_unknown(s) for s in "abcde"])
        assert r.verdict == "unknown"
        assert r.confidence == 0.0

    def test_summary_lists_risk_reasons(self):
        votes = [_risk("goplus", 1.0, ["honeypot flag"]), _risk("scam_db", 1.0, ["2 reports"])]
        votes += [_safe(s) for s in "cde"]
        r = _tally(votes)
        assert "goplus" in r.summary
        assert "honeypot" in r.summary


class TestConsensusVoting:
    """Per-source vote helpers map signals to safe/risk/unknown correctly."""

    def test_goplus_honeypot_votes_risk(self):
        from vigil_mcp.scanners.goplus import GoPlusResult

        gp = GoPlusResult(available=True, is_honeypot=True)
        v = ConsensusEngine()._vote_goplus(gp)
        assert v.vote == RISK

    def test_goplus_clean_votes_safe(self):
        from vigil_mcp.scanners.goplus import GoPlusResult

        gp = GoPlusResult(available=True, is_honeypot=False, buy_tax=0.0, sell_tax=0.0)
        v = ConsensusEngine()._vote_goplus(gp)
        assert v.vote == SAFE

    def test_goplus_unavailable_votes_unknown(self):
        from vigil_mcp.scanners.goplus import GoPlusResult

        gp = GoPlusResult(available=False)
        v = ConsensusEngine()._vote_goplus(gp)
        assert v.vote == UNKNOWN

    def test_scam_reported_votes_risk(self):
        v = ConsensusEngine()._vote_scam({"reported": True, "report_count": 3})
        assert v.vote == RISK

    def test_scam_clean_votes_safe(self):
        v = ConsensusEngine()._vote_scam({"reported": False, "report_count": 0})
        assert v.vote == SAFE

    def test_exception_inputs_are_unknown(self):
        eng = ConsensusEngine()
        assert eng._vote_goplus(Exception("boom")).vote == UNKNOWN
        assert eng._vote_score(Exception("boom")).vote == UNKNOWN
        assert eng._vote_market(Exception("boom")).vote == UNKNOWN
        assert eng._vote_deployer(Exception("boom"), False).vote == UNKNOWN


class TestLiquidityLockVote:
    """Liquidity-lock vote — a 6th independent source. `unknown` must be
    weight 0 so missing lock data does not move the consensus verdict."""

    def test_locked_votes_safe(self):
        from vigil_mcp.scanners.liquidity_lock import LockResult

        lock = LockResult(
            token=TOKEN,
            chain="base",
            available=True,
            determined=True,
            lock_status="locked",
        )
        v = ConsensusEngine()._vote_lock(lock)
        assert v.vote == SAFE
        assert v.weight > 0

    def test_burned_votes_safe(self):
        from vigil_mcp.scanners.liquidity_lock import LockResult

        lock = LockResult(
            token=TOKEN,
            chain="base",
            available=True,
            determined=True,
            lock_status="burned",
        )
        v = ConsensusEngine()._vote_lock(lock)
        assert v.vote == SAFE

    def test_unlocked_votes_risk(self):
        from vigil_mcp.scanners.liquidity_lock import LockResult

        lock = LockResult(
            token=TOKEN,
            chain="base",
            available=True,
            determined=True,
            lock_status="unlocked",
        )
        v = ConsensusEngine()._vote_lock(lock)
        assert v.vote == RISK

    def test_unknown_votes_unknown_with_zero_weight(self):
        """Missing lock data MUST NOT influence the consensus verdict."""
        from vigil_mcp.scanners.liquidity_lock import LockResult

        lock = LockResult(
            token=TOKEN,
            chain="base",
            available=True,
            determined=False,
            lock_status="unknown",
        )
        v = ConsensusEngine()._vote_lock(lock)
        assert v.vote == UNKNOWN
        assert v.weight == 0.0

    def test_unsupported_chain_votes_unknown(self):
        from vigil_mcp.scanners.liquidity_lock import LockResult

        lock = LockResult(
            token=TOKEN,
            chain="solana",
            available=False,
            determined=False,
            lock_status="unknown",
        )
        v = ConsensusEngine()._vote_lock(lock)
        assert v.vote == UNKNOWN

    def test_exception_input_is_unknown(self):
        v = ConsensusEngine()._vote_lock(Exception("boom"))
        assert v.vote == UNKNOWN

    def test_lock_unknown_does_not_shift_safe_verdict(self):
        """End-to-end: 5 safe + 1 lock-unknown ⇒ still safe."""
        votes = [_safe(s) for s in ("goplus", "onchain", "market", "deployer", "scam_db")]
        votes.append(_unknown("liquidity_lock"))
        r = _tally(votes)
        assert r.verdict == "safe"
        assert r.unknown_sources == 1
