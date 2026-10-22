# vectors_hub.json

Verbatim copy of `vectors/vectors_hub.json` of orch-hub (contract `orch.hub/0`, `docs/protocol.md` §15),
sha256 `b7a37f0de46b9b0a08113cf36f54d34f03cb74a65a8f47bfd917e3003424c643`, orch-hub commit `5c04a8e`
(branch `v3-p4-contract`, PR #22: phase-4 extension, includes the `relay_request` cases of §10.8). One shared
file across repos (V3-D8): do not edit here, re-copy from orch-hub. All keys are FAKE and test-only.
The relay runs the `card`, `card_text`, `op_cert` and `op_revoked` cases (`tests/test_hub_accounts_vectors.py`;
cases with a `pinned_root` are skipped: the relay pins no root, a hub account is keyed by `hub_id`, which is derived
from the root) and the 22 `relay_request` cases (`tests/test_hub_relay_requests.py`).
