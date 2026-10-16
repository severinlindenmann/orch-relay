# Relay HTTP v2 examples

These files are shared contract inputs for orch-relay, orch-mobile and orch-core. They cover every
non-checkpoint route in protocol-v2 §19. A separate file covers each bridge/pair POST role. All keys,
tokens, invites, labels and signatures are public **FAKE** test material.

Each file has `contract`, deployment `suite`, `route` (method, template, role, auth) and `cases`.
Each case has `name`, `given` (scenario preconditions, never sent), `request` and `response`.

- Substitute no identifiers: `request.path` already contains concrete ids. `query` is a map of exact
  string values to URL-encode. Omitted query values are absent, not empty strings.
- Send the exact headers and either `cj(request.json)`, decoded `body_b64u`, or no body for GET.
- An over-limit request uses `body_recipe`: decode `prefix_b64u`, append byte `byte` exactly `count`
  times, then decode/append `suffix_b64u`. This specifies exact bytes without megabytes of padding.
  The recipe is fixture metadata; do not send its JSON. Size rejection precedes body parsing.
- `response` has `status`, headers and the exact JSON field set. `Retry-After` is delta-seconds.
- Refusal cases describe the precondition that makes the example fail. Consumers supply that state;
  these are HTTP shape examples, not a database seed format. For example, a valid artifact signed by
  the wrong *trusted* key illustrates `bad_signature`. Suite-mismatch examples contain actual suite-1
  artifacts, valid under their own keys but refused by the suite-2 deployment.
- Signatures are independently verified from `tests/vectors_v2.json`. `p3.cases` contains complete,
  replayable states and expected post-states for the membership, queue, session, revocation, replay,
  quota and holder checks. Failed membership publications leave the input state unchanged.

Drop (P3-D39, D39a1: `drop_put.json`, `drop_list.json`, `drop_descriptors.json`, `drop_descriptor_get.json`,
`drop_wraps_get.json`, `drop_blob_get.json`): the `PUT` body is the binary `ODU2` frame given as `body_hex`; a
blob answer is `response.body_hex`. Preconditions are portable: `given.prior` lists earlier requests (send them
first, each answered 2xx), `given.ops` names state changes without a D39a1 route (`retire` and `expire_sweep`
of D39a2, `claim` of D39b, `prune` after a restore, `foreign_object`, `epoch`, `clock`) and `given.relay` names
in-memory relay conditions (`device`: `drop_scoped`/`cert_expired`/`revoked`; full `upload_slots`,
`read_slots` or `download_slots` of the `device` or the `relay`; an empty `bucket`: the read-class
`empty`, or (D39a2) `drop_up_empty`, the device's MiB upload bucket; `usage`: a `{scope, field}` at its cap,
`creations`: `device_full`, the device's 250 version-1 creations of the UTC day; `decide_budget`: `creations_full` or `bytes_full`, the phone's decide-class budget of the UTC day spent). D39a2 part 3 adds the op `scopes` (`{device, scopes}`: the phone holds `look` and `decide` only) for the decide-class cases of `drop_put.json`, and the `claim` op now also sets `claimed_ms` to the relay's `now` (`drop_list.json`). `drop_retire.json` (D39a2 part 2, the host's retire; the model's `retire` in `ref/drop_relay.py`) names the op `rotation_due` too (an open `rotation_due` row: `drop_put.json` `refusal_409_rotation_required`). Every expected answer is
the reference model's (`ref/drop_relay.py`). `host_poll.json` `drop_notice` shows `notices.drop` (only with
`ORCH_RELAY_DROP_NOTICE=1`, until hosts accept the key).

Push (P3-D40, `push_register.json`, `push_unregister.json`, `push_send.json`): ordinary JSON routes. `given.relay.envs`
names the environments the relay has a key for; the 404 `not_found` of a relay without a complete push configuration
is the `refusal_404_not_found` case of each. The exact APNs request the relay makes is the `push.apns_envelope` vector
(`tests/vectors_v2.json`, suite 2): the outer object becomes the string `o` of a fixed body, at most 3,175 bytes.

Regenerate after the vectors with:

```
uv run python -m ref.orch_protocol_ref
uv run python -m ref._http_fixtures
uv run pytest tests/test_vectors.py tests/test_http_fixtures.py -q
```

Checkpoint/restore/genesis/staging/baseline/proof routes bind their cases to the `checkpoints` and
`checkpoints_g4` vector states (`given.vector`). `unpublished_get.json` and `unpublished_ack.json`
(P3-D31, retrieval of unpublished revocation evidence) bind to the `unpublished` vector group; the
`host_poll.json` cases `unpublished_notice` and `unpublished_notice_acked` show `notices.unpublished`, and
`checkpoint_put.json` `restore_with_unpublished_refs` names the item `unpublished_get.json` `success`
serves. There is no HTTP invite-management route and no rotation-abandon route.
