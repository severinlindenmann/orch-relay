# vectors_hub.json

Verbatim copy of `vectors/vectors_hub.json` of orch-hub (contract `orch.hub/0`, `docs/protocol.md` §15),
sha256 `16280835cbd4eec6c260cd96c374c088345b850d3b29182f9c35a8b56ee0620a`, orch-hub commit `80f296b`
(PR #2). One shared file across repos (V3-D8): do not edit here, re-copy from orch-hub. All keys are FAKE
and test-only. The relay runs the `card`, `card_text`, `op_cert` and `op_revoked` cases
(`tests/test_hub_accounts_vectors.py`); cases with a `pinned_root` are skipped (the relay pins no root: a
hub account is keyed by `hub_id`, which is derived from the root).
