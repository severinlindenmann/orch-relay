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

Regenerate after the vectors with:

```
uv run python -m ref.orch_protocol_ref
uv run python -m ref._http_fixtures
uv run pytest tests/test_vectors.py tests/test_http_fixtures.py -q
```

Checkpoint/restore/genesis/staging/baseline/proof routes are intentionally deferred to the next
contract group. There is no HTTP invite-management route and no rotation-abandon route.
