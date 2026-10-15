"""The shipped verifier consumes the shared contract without importing test support."""

import json
from pathlib import Path

import pytest

from orch_relay import proto as P

V = json.loads(Path("tests/vectors_v2.json").read_text())
S = V["suites"]["2"]


@pytest.mark.parametrize("c", V["encodings"]["canonical_json"])
def test_canonical(c):
    assert P.cj(c["value"]).hex() == c["bytes"]


@pytest.mark.parametrize("c", V["encodings"]["strict_parse"])
def test_parse(c):
    try:
        P.parse_json(c["text"].encode())
        ok = True
    except ValueError:
        ok = False
    assert ok == c["ok"]


@pytest.mark.parametrize("c", V["encodings"]["b64u"])
def test_b64(c):
    try:
        got = P.unb64u(c["text"]).hex()
    except ValueError:
        got = None
    assert got == c["bytes"]


@pytest.mark.parametrize("c", S["sign"])
def test_sign(c):
    assert (
        P.SUITE.verify(bytes.fromhex(c["pub"]), bytes.fromhex(c["sig"]), bytes.fromhex(c["msg"]))
        == c["valid"]
    )


@pytest.mark.parametrize("c", S["certs"]["cases"])
def test_cert(c):
    assert (
        P.verify_cert(c["signed"], bytes.fromhex(c["pk_pub"]), c["now_ms"], set(c["revoked"]))
        == c["expect"]
    )


@pytest.mark.parametrize("c", S["revocations"])
def test_revocation(c):
    assert P.verify_revocation(c["signed"], bytes.fromhex(c["pk_pub"]), c["cert"]) == c["expect"]


@pytest.mark.parametrize("c", S["card"]["cases"])
def test_card(c):
    assert (
        P.relay_accept_card(c["stored"], c["card"], bytes.fromhex(c["owner_pk_pub"])) == c["expect"]
    )


def test_no_reference_import():
    import subprocess
    import sys

    subprocess.run(
        [
            sys.executable,
            "-c",
            'import sys; import orch_relay.app; assert not any(k == "ref" or k.startswith("ref.") for k in sys.modules)',
        ],
        check=True,
    )
