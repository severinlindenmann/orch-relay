import json
import pathlib

import pytest

from orch_relay import hub_accounts

V = json.loads((pathlib.Path(__file__).parent / "vectors" / "origin_http.json").read_text())


@pytest.mark.parametrize("o", V["accept"])
def test_accept(o):
    assert hub_accounts._URL.fullmatch(o)


@pytest.mark.parametrize("o", V["refuse"])
def test_refuse(o):
    assert not hub_accounts._URL.fullmatch(o)
