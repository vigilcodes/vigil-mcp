"""Tests for the first-party x402 paying client (vigil_mcp.payments.client).

Verifies, without moving funds, that:
  - the payment payload defaults to echoing VIGIL's configured app code,
  - an explicit app code overrides the default,
  - network aliases resolve, value is correct, signature recovers, and
  - unsupported networks fail loudly.
"""

import base64
import json

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from vigil_mcp.payments import client as pay_client

TEST_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
PAY_TO = "0x" + "a" * 40


@pytest.fixture
def account():
    return Account.from_key(TEST_KEY)


def test_defaults_to_configured_app_code(account, monkeypatch):
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
    payload = pay_client.build_payment_payload(account, network="base", pay_to=PAY_TO, price_usd=0.005)
    assert payload["extensions"]["builder-code"]["info"]["a"] == "bc_kz42eeiy"


def test_explicit_app_code_overrides(account, monkeypatch):
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
    payload = pay_client.build_payment_payload(
        account, network="base", pay_to=PAY_TO, price_usd=0.005, app_code="bc_other"
    )
    assert payload["extensions"]["builder-code"]["info"]["a"] == "bc_other"


def test_no_extension_when_no_code(account, monkeypatch):
    monkeypatch.delenv("VIGIL_X402_APP_CODE", raising=False)
    payload = pay_client.build_payment_payload(account, network="base", pay_to=PAY_TO, price_usd=0.005)
    assert "extensions" not in payload


def test_service_codes_attached(account, monkeypatch):
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
    payload = pay_client.build_payment_payload(
        account, network="base", pay_to=PAY_TO, price_usd=0.005, service_codes=["bc_mcp"]
    )
    assert payload["extensions"]["builder-code"]["info"]["s"] == ["bc_mcp"]


def test_network_alias_and_value(account):
    payload = pay_client.build_payment_payload(account, network="base", pay_to=PAY_TO, price_usd=0.005, app_code="")
    assert payload["accepted"]["network"] == "eip155:8453"
    assert payload["accepted"]["amount"] == "5000"
    assert payload["payload"]["authorization"]["value"] == "5000"
    # 0x-prefixed signature is required by the CDP schema.
    assert payload["payload"]["signature"].startswith("0x")


def test_unsupported_network_raises(account):
    with pytest.raises(ValueError):
        pay_client.build_payment_payload(account, network="eip155:1", pay_to=PAY_TO, price_usd=0.005)


def test_signature_recovers_to_payer(account):
    payload = pay_client.build_payment_payload(account, network="base", pay_to=PAY_TO, price_usd=0.005, app_code="")
    auth = payload["payload"]["authorization"]
    usdc, name = pay_client.USDC_BY_NETWORK["eip155:8453"]
    from eth_utils import to_checksum_address

    typed = pay_client._eip3009_typed_data(
        8453,
        to_checksum_address(usdc),
        name,
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


def test_encode_payment_header_roundtrips(account, monkeypatch):
    monkeypatch.setenv("VIGIL_X402_APP_CODE", "bc_kz42eeiy")
    payload = pay_client.build_payment_payload(account, network="base", pay_to=PAY_TO, price_usd=0.005)
    header = pay_client.encode_payment_header(payload)
    assert json.loads(base64.b64decode(header)) == payload
