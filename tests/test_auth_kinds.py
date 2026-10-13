"""H12d (P3-D38): `auth: "convenience"` in restore evidence, relay and reference alike.

The relay's restore-line parse (R0, P3-D13) refuses any `auth` kind it does not know. Level 1 of the
reader-version handshake (orch-core orch-v2-host §9.8) means this parser holds `convenience` (F1 §11.4
with the H5c amendment) and still refuses every unknown kind. Parse only: the relay never acts on a
kind. The core-owned F1 checkpoint vectors do not carry a convenience case yet (orch-core adds them,
§9.12); these are the relay's own unit checks, and the relay-owned `checkpoints` vector group carries a
signed convenience restore end to end (tests/test_checkpoint_vectors.py replays it in production).
FAKE keys only.
"""

import copy
import json

import pytest

from orch_relay import checkpoints as P_CP
from orch_relay.directory import Refusal
from ref import checkpoints as C
from ref import orch_protocol_ref as R

VEC = json.loads(R.VECTORS.read_text(encoding="utf-8"))
OLD_KINDS = (
    "passphrase",
    "secure-enclave",
    "secure-enclave-unlocked",
    "webauthn",
    "tpm",
    "windows-hello",
)


def line_with(auth):
    line = copy.deepcopy(VEC["suites"]["2"]["checkpoints"]["objects"]["restore"]["line"])
    line["auth"] = auth
    return line


def relay_accepts(line):
    try:
        P_CP.Relay.restore_shape(line)
        return True
    except Refusal:
        return False


def ref_accepts(line):
    try:
        C.restore_shape(line)
        return True
    except C.Refusal:
        return False


def test_relay_and_reference_kinds_agree_and_include_convenience():
    assert P_CP.AUTH_KINDS == C.AUTH_KINDS
    assert P_CP.AUTH_KINDS == OLD_KINDS + ("convenience",)


@pytest.mark.parametrize("auth", OLD_KINDS + ("convenience",))
def test_every_known_kind_passes_the_restore_shape(auth):
    assert relay_accepts(line_with(auth)) and ref_accepts(line_with(auth))


@pytest.mark.parametrize(
    "auth",
    ["bogus", "Convenience", "convenience ", "", None, 1, ["convenience"], {"convenience": 1}],
)
def test_an_unknown_kind_is_still_refused(auth):
    """Level 1's second half: an unknown kind is refused, never mapped to a known one."""
    assert not relay_accepts(line_with(auth)) and not ref_accepts(line_with(auth))


def test_relay_restore_shape_refuses_an_unknown_kind_as_malformed():
    """restore_shape's own refusal; the publication answers it as `restore_invalid` (R0)."""
    with pytest.raises(Refusal) as e:
        P_CP.Relay.restore_shape(line_with("bogus"))
    assert (e.value.status, e.value.code) == (400, "malformed")


def test_the_signed_convenience_restore_vector_is_accepted_and_unknown_refused():
    """The relay-owned vectors carry both cases fully signed (ref/_checkpoint_vectors.py)."""
    for sid in ("1", "2"):
        cases = {c["name"]: c for c in VEC["suites"][sid]["checkpoints"]["cases"]}
        ok, bad = cases["restore_auth_convenience_accepted"], cases["restore_auth_unknown_refused"]
        assert ok["steps"][-1]["input"]["body"]["restore"]["line"]["auth"] == "convenience"
        assert "error" not in ok["steps"][-1]["expect"]
        assert bad["steps"][-1]["input"]["body"]["restore"]["line"]["auth"] == "bogus"
        assert bad["steps"][-1]["expect"]["error"] == "restore_invalid"
