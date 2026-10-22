# vectors_hub.json

Verbatim copy of `vectors/vectors_hub.json` of orch-hub (contract `orch.hub/0`, `docs/protocol.md` §15),
sha256 `5360cf45b4c1f980dbfbe728a414fdfaf7302aa3183327a8464d38e919f2d506`, orch-hub `develop` at `bfa95a0` (PR orch-hub#27 merged: the 25 `relay_route` cases and `phase4.relay_routes` of §10.8.1/§10.8.2 on top of
the phase-4 contract of PR #22; D10 round 2 changed text only, the bytes are the same as `1081994`). One shared
file across repos (V3-D8): do not edit here, re-copy from orch-hub. All keys are FAKE and test-only.
The relay runs the `card`, `card_text`, `op_cert` and `op_revoked` cases (`tests/test_hub_accounts_vectors.py`;
cases with a `pinned_root` are skipped: the relay pins no root, a hub account is keyed by `hub_id`, which is derived
from the root) the 24 `relay_request` cases (`tests/test_hub_relay_requests.py`) and the 25 `relay_route` cases plus the signed
requests of `phase4.relay_routes` (`tests/test_hub_phone.py`).
