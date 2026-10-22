# vectors_hub.json

Verbatim copy of `vectors/vectors_hub.json` of orch-hub (contract `orch.hub/0`, `docs/protocol.md` §15),
sha256 `ffb6b2b8f43c8faaf03ca9ad43329d5490a631a95d8a0470c30784400d38b4ac`, orch-hub `develop` at `28f46b5`
(PR #22 merged, follow-up `29bf048`: phase-4 contract, 584 vectors, `relay_request` cases of §10.8). One shared
file across repos (V3-D8): do not edit here, re-copy from orch-hub. All keys are FAKE and test-only.
The relay runs the `card`, `card_text`, `op_cert` and `op_revoked` cases (`tests/test_hub_accounts_vectors.py`;
cases with a `pinned_root` are skipped: the relay pins no root, a hub account is keyed by `hub_id`, which is derived
from the root) and the 24 `relay_request` cases (`tests/test_hub_relay_requests.py`).
