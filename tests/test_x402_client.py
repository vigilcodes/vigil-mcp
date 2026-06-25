"""Tests for the builder-code-aware x402 paying client (scripts/x402_pay_client.py).

These verify the two things that matter without moving any funds:
  1. the EIP-3009 signature recovers to the payer (so the facilitator would
     accept it), and
  2. the X-PAYMENT payload echoes the app code (``a``) — the piece that gets
     VIGIL's Builder Code onchain.
"""

import importlib.util
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

# Load the client script as a module (it lives in scripts/, not a package).
_CLIENT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "x402_pay_client.py"
_spec = importlib.util.spec_from_file_location("x402_pay_client", _CLIENT_PATH)
client = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(client)

# Deterministic throwaway test key (NOT a real wallet).
TEST_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
PAY_TO = "0x" + "a" * 40


@pytest.fixture
def account():
    return Account.from_key(TEST_KEY)


def test_payload_echoes_app_code(account):
    payload = client.build_signed_payment(
        account,
        network="base-sepolia",
        pay_to=PAY_TO,
        price_usd=0.005,
        app_code="bc_kz42eeiy",
        service_codes=[],
    )
    info = payload["extensions"]["builder-code"]["info"]
    assert info["a"] == "bc_kz42eeiy"
    assert "s" not in info


def test_payload_includes_service_codes(account):
    payload = client.build_signed_payment(
        account,
        network="base-sepolia",
        pay_to=PAY_TO,
        price_usd=0.005,
        app_code="bc_kz42eeiy",
        service_codes=["bc_mcp"],
    )
    assert payload["extensions"]["builder-code"]["info"]["s"] == ["bc_mcp"]


def test_no_extension_without_app_code(account):
    payload = client.build_signed_payment(
        account,
        network="base-sepolia",
        pay_to=PAY_TO,
        price_usd=0.005,
        app_code="",
        service_codes=[],
    )
    assert "extensions" not in payload


def test_signature_recovers_to_payer(account):
    """The EIP-3009 signature must recover to the payer, or the facilitator rejects it."""
    payload = client.build_signed_payment(
        account,
        network="base-sepolia",
        pay_to=PAY_TO,
        price_usd=0.005,
        app_code="bc_kz42eeiy",
        service_codes=[],
    )
    auth = payload["payload"]["authorization"]
    chain_id = int(client.CAIP2["base-sepolia"].split(":")[1])
    typed = client._eip3009_typed_data(
        chain_id,
        client.USDC["base-sepolia"],
        client.USDC_NAME["base-sepolia"],
        auth["from"],
        auth["to"],
        int(auth["value"]),
        int(auth["validAfter"]),
        int(auth["validBefore"]),
        auth["nonce"],
    )
    recovered = Account.recover_message(
        encode_typed_data(full_message=typed), signature=payload["payload"]["signature"]
    )
    assert recovered.lower() == account.address.lower()


def test_value_matches_price_in_atomic_units(account):
    payload = client.build_signed_payment(
        account,
        network="base",
        pay_to=PAY_TO,
        price_usd=0.005,
        app_code="bc_kz42eeiy",
        service_codes=[],
    )
    # 0.005 USDC * 1e6 = 5000 atomic units
    assert payload["payload"]["authorization"]["value"] == "5000"
    assert payload["accepted"]["network"] == "eip155:8453"
    assert payload["accepted"]["amount"] == "5000"
