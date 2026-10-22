# vectors_hub.json

Verbatim copy of `vectors/vectors_hub.json` of orch-hub (contract `orch.hub/0`, `docs/protocol.md` §15),
sha256 `a854ae4d7080719c48c136cb6c137083bb8a165ed25d3d1ecc98b34c71b17ebe`, orch-hub `develop` at `4edf42d` (contract B:
§6.4 channel sessions, §10.8.4 channel mailbox read, §10.8.3 cut-over, §10.8.1/§10.8.2 hub push and mailbox). Earlier copies:
`v3-p4-addendum` at `f10a457`; `develop` at `bfa95a0` (PR orch-hub#27). One shared file across repos (V3-D8): do not
edit here, re-copy from orch-hub. All keys are FAKE and test-only.
The relay runs the `card`, `card_text`, `op_cert` and `op_revoked` cases (`tests/test_hub_accounts_vectors.py`;
cases with a `pinned_root` are skipped: the relay pins no root, a hub account is keyed by `hub_id`, which is derived
from the root) the 24 `relay_request` cases (`tests/test_hub_relay_requests.py`) and the 25 `relay_route` cases plus the signed
requests of `phase4.relay_routes` (`tests/test_hub_phone.py`).

The relay also replays the 8 `relay_route_cutover_*` and 12 `cutover_*` cases (`tests/test_cutover_gate.py`), and, from
E5, the 25 `channel_request_*` and 8 `channel_route_*` cases plus the signed bytes of `phase4.channel_api.channel_request`
(`tests/test_hub_channels.py`).
