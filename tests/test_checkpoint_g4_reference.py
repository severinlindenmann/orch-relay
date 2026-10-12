"""The checkpoints_g4 vector group replays against the reference (as test_vectors does for G0b)."""

import pytest
from checkpoint_support import S, cases

from ref._checkpoint_vectors import replay


@pytest.mark.parametrize("case", cases("checkpoints_g4"), ids=lambda c: c["name"])
def test_g4_vector_replays_in_the_reference(case):
    assert replay(S, case) == case["expect"]
