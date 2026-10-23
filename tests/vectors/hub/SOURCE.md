# vectors_hub.json

Verbatim copy of `vectors/vectors_hub.json` of orch-hub (contract `orch.hub/0`, `docs/protocol.md` §15),
sha256 `d1f00f1bec0e166f009e8bba63f905b22977c32a1f1416bbf750d078e29dd470`, orch-hub `v3-e5r1-contract` at `79bf331`
(PR orch-hub#50, E5R-1: the mailbox purge is exempt from the push-configuration 404, 11 `relay_route_nopush_*` cases).
Earlier copies: `develop` at `4edf42d` (contract B: §6.4 channel sessions, §10.8.4 channel mailbox read, §10.8.3
cut-over, §10.8.1/§10.8.2 hub push and mailbox); `v3-p4-addendum` at `f10a457`; `develop` at `bfa95a0` (PR orch-hub#27). One shared file across repos (V3-D8): do not
edit here, re-copy from orch-hub. All keys are FAKE and test-only.
The relay runs the `card`, `card_text`, `op_cert` and `op_revoked` cases (`tests/test_hub_accounts_vectors.py`;
cases with a `pinned_root` are skipped: the relay pins no root, a hub account is keyed by `hub_id`, which is derived
from the root) the 24 `relay_request` cases (`tests/test_hub_relay_requests.py`) and the 36 `relay_route` cases (25 plus the 11
`relay_route_nopush_*` cases of a relay without push configuration, `args.push_configured: false`) plus the signed
requests of `phase4.relay_routes` (`tests/test_hub_phone.py`).

The relay also replays the 8 `relay_route_cutover_*` and 12 `cutover_*` cases (`tests/test_cutover_gate.py`), and, from
E5, the 25 `channel_request_*` and 8 `channel_route_*` cases plus the signed bytes of `phase4.channel_api.channel_request`
(`tests/test_hub_channels.py`).
