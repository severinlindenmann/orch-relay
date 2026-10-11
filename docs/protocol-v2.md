# orch protocol, version 2

This document is the wire contract of orch v2. It fixes the exact bytes that the three implementations
exchange, and what each of them does with an input that is not right:

- **orch-core**: the workspace host (`orch serve` / `orch host`);
- **orch-relay**: directory, relay (bridge v2), drop and push;
- **orch-mobile**: the native app (D45/D46, P3 design §7).

orch-publish implements §12.1.

Status: **draft for review**, written for P0 of the orch v2 plan. The design it implements is
`orch-core/docs/architecture/orch-v2.md` ("the spec"; §-references to it are written *spec §n*). The spec
is the source of truth for *what* is built. This document decides *how it looks on the wire*. Where this
document had to choose something the spec leaves open, the choice is marked **DECIDED HERE:**, and §17
lists every such choice. A reviewer should read §17 first.

The contract is [`tests/vectors_v2.json`](../tests/vectors_v2.json). The reference implementation that
produces it, [`ref/orch_protocol_ref.py`](../ref/orch_protocol_ref.py) and its builder `ref/_vectors.py`,
is **test support only and is never shipped or imported by shipped code**. Where the reference and this
document disagree, this document wins and the reference has a bug. As in bridge v1, every side tests
against the vectors, not against the other sides. Run `uv run pytest tests/test_vectors.py -x -q` to
check that the reference reproduces the file and that every case replays from its JSON.

Conventions:

- Integers on the wire are unsigned big-endian unless a field says otherwise.
- `||` is concatenation.
- Labels are ASCII byte strings written in double quotes.
- `H(x)` is SHA-256.
- "hex" is lower case; "b64u" is canonical base64url without padding (§2.2).
- `lp16(x)` is a 2-byte length followed by `x`; `u8`, `u32` and `u64` are integers of 1, 4 and 8 bytes.
- "MUST" and "MUST NOT" are requirements; everything else is explanation.

## Changes since bridge v1

Bridge v1 (`orch-tix/docs/bridge-protocol.md`, with its vectors and reference) is the base. Version 2
keeps v1's good parts unchanged in substance:

- encrypt-then-sign envelopes with a 16-byte salt per message and a zero nonce;
- the plaintext framing (`meta_len || meta || data`) and strict request meta;
- sequence windows and the request store;
- the silence-before-the-tag rule and the refusal budgets;
- the clock-offset rule;
- the pinned host key;
- the WebAuthn binding, and the `shown` cleaning.

What changes:

- **Keys.** A random workspace key `WK_e` per epoch, sealed to each member device (spec D2). `MK` no
  longer exists. Every use of `WK_e` goes through HKDF with its own label (§3). `K_bridge` replaces
  `K_ws`.
- **Suites (D46, P3 design §7).** Suite 2 (P-256) is the only deployment suite. Suite 1 remains
  test-only; suites are never negotiated (§1).
- **Header.** The magic is now `"ORB2"`, the version 2. The `key_version` byte becomes `suite`, and a 4-byte
  `epoch` is added before the salt: 108 bytes in all (§8.1). v1 envelopes are dropped.
- **Identities.**
  - The device key comes from a device certificate signed by the person key `PK` (§6).
  - The host key is the workspace signing key `WSK`, pinned through the pairing link and the card.
  - Device ids derive from the device's signing key alone. They no longer include the workspace,
    because the relay must link a device across workspaces to enforce revocations (§4).
- **Pairing.**
  - The link carries `PK`'s pin too, and the pairing request is sealed under a key derived from the link
    secret (epoch 0).
  - v1's MAC is gone: the AEAD tag proves the secret.
  - The fingerprint is a 6-character code bound to a host nonce, the `cert_pending` state is new, and so is
    the request to the primary device. The primary answers that request with a `PK`-signed challenge that
    the phone checks against its own keys (§8.3, §8.4).
- **Refusals.**
  - `not_paired` becomes `not_member`.
  - New codes: `stale_epoch`, `other_person`, `cert_invalid`, `cert_expired`, `already_answered` and
    `question_changed` (§14).
  - Every refusal to an epoch-0 request carries `wsk_pub`, where v1 carried `host_pub`.
- **New constructions:**
  - sealing to a device or to a workspace exchange key (§5.3);
  - certificates and revocations (§6);
  - cards, member lists and WK grants (§7);
  - push payloads (§9);
  - Drop content, wraps, claims and documents (§10);
  - ws→ws envelopes (§11);
  - publish request signing (§12).

## 1. Suites

### 1.1 The two suites

**D45/D46 (P3 design §7).** Deployments MUST use suite 2. Suite 1 and its vectors are test-only.
Native devices use platform cryptography; references below to browser/WebCrypto behavior describe
the historical suite-1 client, not a deployment requirement.

| | Suite 1 `ed25519-x25519` (test-only, D46) | Suite 2 `p256` (deployment, D46) |
|---|---|---|
| Signature | Ed25519 (RFC 8032, pure), 64 bytes | ECDSA P-256 with SHA-256, raw `r \|\| s`, 64 bytes (IEEE P1363) |
| Signing public key | 32 bytes | 65 bytes, uncompressed point |
| Key agreement | X25519, 32-byte keys, 32-byte shared secret | ECDH P-256, 65-byte keys, the 32-byte x-coordinate |
| Hash, KDF, AEAD | SHA-256; HKDF-SHA-256 (RFC 5869); AES-256-GCM with a 96-bit nonce and a 128-bit tag | the same |

Primitives come only from WebCrypto and the Python `cryptography` package. There is no compression
anywhere.

- **One suite per deployment, never negotiated (spec D22).** A relay is configured with one suite id. Its
  directory, every certificate, card and member list, and every header carry that id. A verifier MUST
  compare the id with its own configured suite, and MUST drop (or refuse as `wrong_suite` at an HTTP API)
  anything else. Nobody ever tries a second suite. The suite id is in the AAD and in the signed bytes of
  every construction, so it cannot be changed in transit.
- Switching a deployment from one suite to the other is a fresh start: new keys, new ids and new
  pairings. **DECIDED HERE:** suite ids are `1` and `2`. They are carried as one byte in binary layouts and
  as the integer `suite` in JSON objects.
- Each device holds **two** key pairs: a signing key `dk_sig` and a key-agreement key `dk_kx`. A workspace
  likewise has `WSK` (signing) and `WXK` (key agreement). **DECIDED HERE:** the spec's "DK, signing + key
  agreement" is two keys, because neither Ed25519/X25519 nor WebCrypto allows one key for both uses. Both
  private halves are non-extractable on a browser.

### 1.2 Validation

**Suite 1.**

- A signature is accepted only if:
  - it is 64 bytes;
  - its `S` (the last 32 bytes, little-endian) is below the group order `L`;
  - the public key passes the next rule;
  - then RFC 8032 verification passes.
- A public signing key MUST be:
  - 32 bytes;
  - a canonical encoding (`y < p`, and not `x = 0` with the sign bit set);
  - decodable;
  - **not of small order**.

  The 8 canonical small-order encodings are listed in the vectors as `ed25519_small_order`. A browser
  that cannot do point arithmetic MUST check the encoding against that list, plus the canonical-encoding
  rule. Vectors: `sign` (`s_plus_l_not_canonical`, `small_order_public_key`, `identity_public_key`,
  `non_canonical_y_public_key`).
- An X25519 agreement whose shared secret is all zero MUST fail. WebCrypto and `cryptography` both raise
  on it.

**Suite 2.** This is bridge v1 §3.4 unchanged:

- A signature MUST be 64 bytes, with `r` and `s` in `1 … n-1`.
- A public key MUST be a 65-byte uncompressed point on the curve.
- ECDSA is malleable (`(r, n−s)` verifies; vector `high_s_twin_verifies`), so no signature is ever used as
  an identifier, in either suite.

**Both suites.** The reference signs deterministically (Ed25519 always is; ECDSA via RFC 6979) only so
that the vectors are reproducible. A real signer may randomise.

## 2. Encodings

### 2.1 Binary

Binary layouts (headers, AADs, signed byte strings) are defined field by field below. Ids are always 16
raw bytes in binary and 32 hex characters in text.

### 2.2 Text forms of bytes

- **hex** is used for ids (16 bytes) and nothing else in JSON. It MUST be lower case and of the exact
  length.
- **b64u** is used for every other byte string in JSON: keys, signatures, ciphertexts, hashes and nonces.
  It MUST be canonical. A decoder MUST refuse:
  - padding;
  - the standard alphabet (`+`, `/`);
  - a length of `4k+1`;
  - non-zero trailing bits (`"AAF"` is not `"AAE"`).

  It MUST also check the decoded length where the field has one. Vectors: `encodings.b64u`.

**DECIDED HERE:** ids in hex and every other byte string in b64u, as in v1's meta and TIX's links.

### 2.3 JSON

Every JSON object that is signed, sealed, or carried in a bridge meta uses one subset, and one canonical
form.

**The subset.**

- Values are objects, arrays, strings, booleans, `null`, and integers in `±(2^53 − 1)`.
- **No floating-point numbers at all.** `1.0` and `1e3` are refused, even though they denote integers.
- Object keys are non-empty ASCII.
- Strings are Unicode scalar values only: no lone surrogates.
- Nesting is at most 16 levels: the root container is level 1, so 16 nested containers are accepted and 17 are
  refused (a scalar adds no level).

**DECIDED HERE:** the subset rules (no floats, ASCII keys, safe integers). With them, JavaScript and
Python produce the same bytes without special cases: with ASCII keys, sorting by code point and sorting by
UTF-16 unit agree.

**Canonical form** (`cj`): TIX's `canonicalJson`, that is, Python's
`json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8.

**Strict parsing.** A receiver MUST parse with every one of these refused:

- a duplicate key;
- `NaN` or `Infinity`;
- a float;
- an integer outside the safe range;
- a non-ASCII key;
- invalid UTF-8.

Vectors: `encodings.strict_parse` (including `depth_16`, `depth_17` and `minus_zero`, where `-0` parses to the
integer `0` and is written `0`), `encodings.canonical_json`.

**Signatures cover `cj(o)`, not the received bytes.** The verifier re-serialises the strictly parsed object
and verifies over that. Because the subset has one canonical form, a signer that signs `cj(o)` and a
verifier that re-serialises agree.

### 2.4 Signed objects

A signed object travels as `{"o": <object>, "sig": <b64u>}`, with exactly those two keys.

- Every object carries `"v": 2`, `"suite"` and `"kind"`.
- `sig = Sign(key, label(kind) || cj(o))`, where `label(kind)` comes from §3.
- A verifier MUST check, before anything else:
  - the two keys;
  - `v`, `suite` and `kind`;
  - the signature.
- Each kind then has an **exact field set**: an object with an extra or a missing field is refused.

The card (§7.1) is the one exception to this shape: it carries a delegation and a sealed part beside `o` and `sig`.

### 2.5 Text that a person reads

Labels (device names, pairing labels) and WebAuthn `shown` text are cleaned as bridge v1 §9.3 says:

- remove every code point of category Cc (except LF), Cf, Zl, Zp, Co and Cn;
- remove every Default_Ignorable_Code_Point;
- do not normalise;
- truncate to **80 code points**.

The receiving host cleans. A displaying device does not clean again. Vector:
`pair_with_a_label_full_of_controls`.

## 3. Domain separation

Every derivation, signature, AEAD associated data, hash and MAC has its own label. Rules:

- **HKDF `info`** is `label` followed by fields, each field preceded by `"|"`. A field is one of:
  - an id as 32 hex characters;
  - an integer in decimal ASCII without leading zeros;
  - a purpose name from a closed list.

  Example: `"orch/v2/bridge|3e7a…b890|2"`.
- **Signed bytes, AADs, hashes and MACs** are `label || bytes`. Their labels end in `"|"`, and no one of
  them is a prefix of another (checked by `test_no_signature_or_aad_label_is_a_prefix_of_another`).
- **`WK_e`, `SK_e`, `DEK`, `CK`, `PVK` and the pairing secret `S` are never used directly** as an AEAD or
  MAC key. Each use goes through HKDF with its own label (spec §6.2).
- An empty HKDF salt means 32 zero bytes (RFC 5869 §2.2), as in WebCrypto.

| Name in vectors | Label | Kind | IKM / signer | Output, or what it covers |
|---|---|---|---|---|
| `kdf_bridge` | `orch/v2/bridge` + `\|ws\|epoch` | HKDF | `WK_e` | `K_bridge`, the bridge channel key (spec §6.2) |
| `kdf_bridge_msg` | `orch/v2/bridge-msg` | HKDF, salt = header salt | `K_bridge` or `K_pair` | `K_msg`, one envelope |
| `kdf_push` | `orch/v2/push` + `\|ws\|epoch` | HKDF | `WK_e` | `K_push` (spec §6.3) |
| `kdf_push_msg` | `orch/v2/push-msg` | HKDF, salt = 16 random bytes | `K_push` | one push payload |
| `kdf_wrap_wk` | `orch/v2/wrap-wk` + `\|ws\|epoch` | HKDF | `WK_e` | key for DEK wraps under the workspace |
| `kdf_wrap_sk` | `orch/v2/wrap-sk` + `\|space\|epoch` | HKDF | `SK_e` | key for DEK wraps under a shared space |
| `kdf_wrap_msg` | `orch/v2/wrap-msg` | HKDF, salt = 16 random bytes | either wrap key | one wrap |
| `kdf_pair` | `orch/v2/pair` + `\|ws\|offer` | HKDF | link secret `S` | `K_pair`, the epoch-0 channel key |
| `kdf_seal` | `orch/v2/seal` + `\|purpose\|recipient` | HKDF, salt = `eph_pub \|\| rcpt_pub` | the shared secret | a sealing key (spec §5.1) |
| `kdf_card` | `orch/v2/card` + `\|ws\|card_seq` | HKDF | card key `CK` | key for the card's sealed part |
| `kdf_drop_content` | `orch/v2/drop-content` + `\|object\|version` | HKDF | `DEK` | content key |
| `kdf_drop_meta` | `orch/v2/drop-meta` + `\|object\|version` | HKDF | `DEK` | metadata key |
| `kdf_label` | `orch/v2/label` + `\|person` | HKDF | personal vault key `PVK` | the label key |
| `kdf_label_msg` | `orch/v2/label-msg` | HKDF, salt = 16 random bytes | the label key | one sealed label |
| `aad_seal` | `orch/v2/seal-aad\|` | AAD | | §5.3 |
| `aad_push` | `orch/v2/push-aad\|` | AAD | | §9 |
| `aad_wrap` | `orch/v2/wrap-aad\|` | AAD | | §10.3 |
| `aad_card` | `orch/v2/card-aad\|` | AAD | | §7.1 |
| `aad_label` | `orch/v2/label-aad\|` | AAD | | §5.4 |
| `aad_drop_meta` | `orch/v2/drop-meta-aad\|` | AAD | | §10.2 |
| `sig_device_cert` | `orch/v2/sig/device-cert\|` | signature | `PK` | device certificate |
| `sig_revocation` | `orch/v2/sig/revocation\|` | signature | `PK` | revocation |
| `sig_card_wsk` | `orch/v2/sig/card-wsk\|` | signature | `WSK` | card (every `card_seq`) |
| `sig_ws_delegation` | `orch/v2/sig/ws-delegation\|` | signature | owner's `PK` | the one-time workspace delegation (§7.1) |
| `sig_cert_challenge` | `orch/v2/sig/cert-challenge\|` | signature | owner's `PK` | the primary's challenge (§8.4) |
| `sig_push` | `orch/v2/sig/push\|` | signature | `WSK` | push payload (§9) |
| `sig_decision` | `orch/v2/sig/decision\|` | signature | `dk_sig` | detached signature of a decision (§13) |
| `sig_member_list` | `orch/v2/sig/member-list\|` | signature | `WSK` | member list |
| `sig_wk_grant` | `orch/v2/sig/wk-grant\|` | signature | `WSK` | a `WK_e` sealed to one device |
| `sig_sk_grant` | `orch/v2/sig/sk-grant\|` | signature | the space owner | an `SK_e` sealed to one device |
| `sig_bridge` | `orch/v2/sig/bridge\|` | signature | `dk_sig` (requests), `WSK` (responses) | bridge envelope |
| `sig_cert_request` | `orch/v2/sig/cert-request\|` | signature | `WSK` | request to the primary device |
| `sig_cert_rejection` | `orch/v2/sig/cert-rejection\|` | signature | `PK` | primary rejection (P3-D11, §8.4) |
| `sig_enroll_request` | `orch/v2/sig/enroll-request\|` | signature | the new agent device key | scoped agent enrolment |
| `sig_drop_object` | `orch/v2/sig/drop-object\|` | signature | author `dk_sig` or `WSK` | Drop version descriptor |
| `sig_drop_claim` | `orch/v2/sig/drop-claim\|` | signature | `WSK` | claim |
| `sig_ws_envelope` | `orch/v2/ws-envelope\|` | signature | sender's `WSK` | ws→ws envelope (spec §9, literal) |
| `sig_ws_cosign` | `orch/v2/sig/ws-cosign\|` | signature | phone `dk_sig` | human co-signature |
| `sig_webauthn_bind` | `orch/v2/sig/webauthn-bind\|` | signature | `dk_sig` | binds a passkey to a device |
| `sig_relay_auth` | `orch/v2/sig/relay-auth\|` | signature | `dk_sig` or `WSK` | relay session login |
| `sig_publish` | `orch/v2/publish\|` | signature | `WSK` | publish request (spec §10, literal) |
| `sig_ticket_event` | `orch/v2/sig/ticket-event\|` | signature | `dk_sig` | a person event in a ticket log (ticket format F1 §5.3) |
| `sig_ws_event` | `orch/v2/sig/ws-event\|` | signature | `dk_sig` | a person event in the workspace log (F1 §5.3) |
| `sig_host_event` | `orch/v2/sig/host-event\|` | signature | `WSK` | the host's signature over a log line (F1 §5.5) |
| `sig_genesis_pin` | `orch/v2/sig/genesis-pin\|` | signature | owner device | immutable genesis pin (P3-D18) |
| `h_checkpoint` | `orch/v2/checkpoint-hash\|` | hash | — | `cj(C.o)`, exactly F1 (P3-D13) |
| `h_log_acc` | `orch/v2/log-acc\|` | hash | — | two decoded 32-byte hashes, exactly F1 (P3-D19) |
| `sig_checkpoint` | `orch/v2/sig/checkpoint\|` | signature | `WSK` | a checkpoint (F1 §5.10) |
| `h_device_id` | `orch/v2/id/device\|` | hash | | device id |
| `h_person_id` | `orch/v2/id/person\|` | hash | | person id |
| `h_pin_person` | `orch/v2/pin/person\|` | hash | | `pk_pin` |
| `h_pin_workspace` | `orch/v2/pin/workspace\|` | hash | | `wsk_pin` |
| `h_sas` | `orch/v2/sas\|` | hash | | the 6-character pairing code |
| `h_sas_cert` | `orch/v2/sas-cert\|` | hash | | the 6-character code of the primary's challenge |
| `h_dek_commit` | `orch/v2/dek-commit\|` | hash | | key commitment for a DEK |
| `h_card_key_commit` | `orch/v2/card-key-commit\|` | hash | | key commitment for a card key `CK` |
| `h_wk_commit` | `orch/v2/wk-commit\|` | hash | | key commitment for `WK_e`, the member list's `wk_commit` (§7.2, G2b) |
| `h_drop_parent` | `orch/v2/drop-parent\|` | hash | | a document version's parent link |
| `h_ws_envelope` | `orch/v2/ws-envelope-hash\|` | hash | | what a co-signature covers |
| `h_question` | `orch/v2/question\|` | hash | | a question's `content_hash` |
| `h_section` | `orch/v2/section\|` | hash | | a ticket section's text (F1 §5.6) |
| `h_value` | `orch/v2/value\|` | hash | | `cj` of a `ticket.json` value (F1 §5.6) |
| `h_gate` | `orch/v2/gate\|` | hash | | a gate hash (F1 §5.7) |
| `h_policy` | `orch/v2/policy\|` | hash | | an effective gate policy (F1 §5.6) |
| `h_people` | `orch/v2/people\|` | hash | | the ticket roles a gate depends on (F1 §5.6) |
| `h_question_id` | `orch/v2/question-id\|` | hash | | a question's `qid`, first 16 bytes (F1 §5.6) |
| `h_event` | `orch/v2/event\|` | hash | | an event head: `prev`, `based_on`, genesis (F1 §5.5) |
| `h_grant_secret` | `orch/v2/grant-secret\|` | hash | | the stored hash of a grant secret (F1 §5.6) |
| `h_assert` | `orch/v2/assert\|` | hash | | WebAuthn assertion challenge |
| `h_webauthn_reg` | `orch/v2/webauthn-reg\|` | hash | | WebAuthn registration challenge |
| `mac_enroll` | `orch/v2/enroll\|` | HMAC-SHA-256 | the enrolment code | scoped agent enrolment |

The `sig_ticket_event` … `h_grant_secret` rows come from orch-core's ticket format F1 (§5.6); the table stays
prefix-free with them, and `h_question` is the same label F1 calls the question hash (same preimage; F1 writes the digest as
`sha256:` + hex, §13 as b64u).

The spec writes two signature domains without a trailing `"|"` (`orch/v2/ws-envelope`,
`orch/v2/publish`). **DECIDED HERE:** both get the trailing `"|"` like every other domain, so that the table
stays prefix-free. Every label starts with `orch/v2/`, so nothing here can be confused with v1's
`sharing/…/v1` labels.

## 4. Identifiers, pins and the pairing code

```
person_id  = H("orch/v2/id/person|" || suite || pk_pub)[0:16]
device_id  = H("orch/v2/id/device|" || suite || dk_sig_pub)[0:16]
pk_pin     = H("orch/v2/pin/person|" || suite || pk_pub)                 (32 bytes)
wsk_pin    = H("orch/v2/pin/workspace|" || suite || wsk_pub)             (32 bytes)
workspace_id, offer_id, rid, object_id, request_id, envelope id: 16 CSPRNG bytes
```

**Ids derived from keys.** `person_id` and `device_id` are derived from the key, so an id cannot be claimed
without the key, and every holder can recompute it. The cost is that one device has one id in every
workspace. v1 avoided this, but v2's relay must enforce a revocation across all of a person's workspaces
anyway (spec §5.2). The owner accepted this in review, and spec §4 is being amended to say so.
`workspace_id` is random (spec §5.3).

**The pairing code (SAS).**

```
sas = base32(H("orch/v2/sas|" || suite || workspace_id || offer_id || lp16(dk_sig_pub) || lp16(dk_kx_pub)
               || lp16(wsk_pub) || sas_nonce (32)))[0:6]
```

- It is shown as 6 characters of the RFC 4648 alphabet `A–Z2–7`, which is 30 bits.
- `sas_nonce` is drawn by the host **when it creates the offer**, and revealed **only** in the signed
  `pending` answer to the device that consumed the offer (§8.3). The device's key is therefore fixed before
  anyone outside the host knows the nonce. The offer is single-use, so whoever holds the link gets exactly
  one try, at 2^-30.
- **DECIDED HERE:** the code binds a host nonce. A plain `H(pub)[…6 chars]` (v1's fingerprint idea,
  shortened to the spec's 6 characters) could be ground in seconds by anyone who saw the honest device's
  key. Vectors: `bridge.sas`, `host_cases.pair_first_time`, `pair_answers.pending_accepted_shows_the_code`.
- This code protects the link against whoever else holds it. It cannot protect against the **host**,
  which chooses `sas_nonce`. That is why the primary's confirmation in `cert_pending` uses a second code,
  over a challenge that the primary signs with a nonce of its own (§8.4):

  ```
  cert_code = base32(H("orch/v2/sas-cert|" || suite || cj(challenge.o)))[0:6]
  ```

## 5. Symmetric constructions and sealing

### 5.1 SALTED-AEAD

For keys that many messages share and no one can count for (`K_push`, the wrap keys, the label key):

```
SALTED-AEAD(K, msg_label, aad, pt) = salt (16 CSPRNG bytes)
                                   || AES-256-GCM(HKDF(K, salt, msg_label), nonce = 12 zero bytes, pt, aad)
```

This is v1's per-envelope key construction (Tink's AES-GCM-HKDF), with the same bound: a collision
needs two salts to collide under one `K`, at most `q²/2^129`. The bridge uses the same construction with
the salt in its header (§8.2). A sealer MUST draw the salt freshly for every seal. Vector: `salted_aead`.

### 5.2 Keys and where they live

| Key | Bytes | Made by | Distributed as | Used through |
|---|---|---|---|---|
| `PK` (person) | suite signing key | primary device, once | its public half in the directory account; `pk_pin` in pairing links | signs certificates, revocations, workspace delegations, cert challenges |
| `dk_sig`, `dk_kx` (device) | suite keys | each device | the certificate (§6.1) | requests, co-signatures, relay login / sealed-to |
| `WSK` (workspace) | suite signing key | the host, at workspace creation | the card; `wsk_pin` in pairing links | responses, member lists, grants, claims, ws envelopes, publish |
| `WXK` (workspace exchange) | suite kx key, versioned | the host, rotated with the 90-day epoch | the card (`wxk_pub`, `wxk_version`) | ws→ws bodies, Drop wraps to the workspace |
| `WK_e` | 32 random bytes | the host, per epoch | WK grants (§7.3) | `K_bridge`, `K_push`, the wrap key |
| `SK_e` | 32 random bytes | the space owner, per epoch | SK grants | the shared-space wrap key |
| `DEK` | 32 random bytes | the writer, **per object version** | wraps (§10.3) | content and metadata keys |
| `CK` | 32 random bytes | the host, per `card_seq` | sealed to each device the card is shared with (purpose `card`) | the card's sealed part |
| `PVK` | 32 random bytes | the primary device | sealed to the person's full devices (purpose `vault`) | sealed device labels (§5.4) |
| `S` (pairing secret) | 32 random bytes | the host, per offer | the link fragment only | `K_pair` |

`WSK` does not rotate. **DECIDED HERE:** the spec gives `WSK` no rotation. The relay refuses a card that
changes `wsk_pub` (`wsk_changed`), so a lost `WSK` means a new workspace. A `DEK` is fresh for every
document version (**DECIDED HERE**), so no content key ever encrypts two plaintexts.

### 5.3 Sealing to a device or to a workspace exchange key

This is the HPKE-shaped construction of spec §5.1. Recipients:

- a device: its `dk_kx`, with recipient id `device_id`;
- a workspace: its `WXK` of a given version, with recipient id `workspace_id`.

```
eph            = a fresh key-agreement key pair (MUST be fresh for every seal)
ss             = KX(eph_priv, rcpt_pub)                              (all-zero is an error)
K              = HKDF(IKM = ss, salt = eph_pub || rcpt_pub,
                      info = "orch/v2/seal|" || purpose || "|" || hex(recipient_id))
AAD            = "orch/v2/seal-aad|" || suite (1) || u8(len(purpose)) || purpose || object_id (16)
                 || u32(epoch) || extra
sealed         = eph_pub || AES-256-GCM(K, nonce = 12 zero bytes, pt, AAD)
```

The zero nonce is safe because `K` is single-use: a fresh `eph` gives a fresh `ss`. The salt binds both
public keys, as HPKE's `kem_context` does. A wrong purpose, recipient, object, epoch or key fails the tag
(vectors `seal`, `seal_open`).

**Purposes** (closed list; `object_id`, `epoch` and `extra` per purpose):

| Purpose | Recipient | `object_id` | `epoch` | `extra` | Plaintext |
|---|---|---|---|---|---|
| `wk` | device | workspace_id | epoch | — | `WK_e` (32) |
| `sk` | device | space_id | space epoch | — | `SK_e` (32) |
| `card` | device | workspace_id | card_seq | — | `CK` (32) |
| `cert-request` | the primary device | request_id | 0 | — | `cj(inner)` (§8.4) |
| `drop-dek` | workspace (WXK) or device | object_id | `wxk_version`, or 0 for a device | `u8(1 wxk / 2 device) \|\| u32(version)` | `DEK` (32) |
| `ws-envelope` | workspace (WXK) | envelope id | `wxk_version` | the 60-byte header (§11.1) | `cj(body)` |
| `vault` | device | person_id | 0 | — | `PVK` (32), reserved |

Sealing authenticates nothing about the sender (HPKE base mode). Wherever the sender matters, the sealed
blob sits inside something the sender signs: WK grants (§7.3), cert requests (§8.4), ws envelopes (§11),
Drop descriptors with their DEK commitment (§10.4), and cards with their CK commitment (§7.1).

### 5.4 Sealed device labels

A certificate's `label_sealed`:

```
label_sealed = SALTED-AEAD(HKDF(PVK, "", "orch/v2/label|" || hex(person_id)), "orch/v2/label-msg",
                           "orch/v2/label-aad|" || suite || device_id, UTF-8(label))
```

It is readable by the person's devices that hold `PVK`, and by nobody else (spec §4, "sealed, not
leaked"). Hosts keep the labels they learned at pairing in their own registry. **DECIDED HERE:** the label
is sealed under a key from the personal vault key. The spec names the field `label_sealed` without saying
to whom. Vector: `label_sealed`.

## 6. Device certificates and revocation

### 6.1 Device certificate

**P3-D5.** Certificate upload is session-less and PK-authorized, under the recovery quotas
of §19.1. (G0a review 3) After signature verification, identical `cj(o)` is a free idempotent
repeat (200, no state change), even with a different signature. Different canonical certificate
content for the same device is 409 `cert_conflict`.

A signed object (§2.4), signed by `PK` with `sig_device_cert`, of kind `device_cert`, with exactly these
fields:

| Field | Value |
|---|---|
| `v`, `suite`, `kind` | `2`, the suite, `"device_cert"` |
| `device_id` | hex, MUST equal `device_id(dk_sig_pub)` |
| `person_id` | hex, MUST equal `person_id(pk_pub)` of the signer |
| `dk_sig_pub`, `dk_kx_pub` | b64u, valid keys of the suite (§1.2) |
| `label_sealed` | b64u (§5.4) |
| `created_ms` | integer |
| `expires_ms` | integer greater than `created_ms`, or `null` for none |
| `scopes_max` | see below |

`scopes_max` is either:

- a non-empty **prefix** of `["look", "decide", "operate", "type"]`; or
- exactly one `"drop:<space_id hex>"`, which makes a scoped agent device (spec D15). A scoped agent's
  `expires_ms` MUST NOT be `null`.

**DECIDED HERE:** scopes are v1's ordered levels, written as the list of levels a device holds, so the
spec's plural `scopes` keeps v1's order. The spec's `expires?` is a field that is always present, `null`
when absent, so the canonical form is unique.

A verifier refuses:

- `cert_invalid` for:
  - a bad signature or field set;
  - an id not of its key;
  - bad scopes;
  - `created_ms > now + 300 s`;
- `cert_expired` when `now ≥ expires_ms`;
- `revoked` when a revocation for `device_id` is known.

Vectors: `certs.cases` (16 cases, including a certificate signed under the revocation label).

### 6.2 Revocation

**P3-D5/D7.** Submission is session-less and PK-authorized (§19.1). The relay atomically
deletes sessions, mailboxes, queued responses, grants and card-key wraps and records durable
`rotation_due` obligations (§19.5). Public revocation lookup remains available without a session.
Reason upgrades preserve the stronger reason (`compromised > lost = retired`).

A signed object, signed by `PK` with `sig_revocation`, of kind `revocation`, with exactly the fields
`{v, suite, kind, person_id, device_id, revoked_ms, reason}`. `reason` is one of `lost`, `retired` or
`compromised`.

**The relay MUST:**

- verify it against the account's `PK`;
- check that the device's certificate names the same person;
- store it permanently;
- **at once**:
  - end the device's sessions;
  - delete its mailboxes, its WK and SK grants, and its push subscriptions;
  - refuse it on every route (spec §5.2).

**Pushing a revocation to hosts.** The primary also sends the record to each of the owner's workspaces as
the bridge op `{"op": "revocation", "record": <signed revocation>}`, so hosts do not wait for their next
directory poll. The authority is `PK`'s signature, not the sender: any member may relay the record. The
host checks, in this order:

1. the exact meta shape → `malformed`;
2. the signature with the owner's `PK` → `bad_signature`;
3. the record's field set and reason → `malformed`;
4. `person_id` is the owner → `other_person`.

It then records the device as revoked and removes it from its member list. If the device was a member, or was
sent a grant for the current epoch in any publication body the host exposed (§7.2 H5, G2b), it **rotates** before
it seals anything new.

**Hosts and devices.** A host that learns of a revocation (through this op, its directory poll, or at
startup) MUST rotate its epoch (§7.2) before it seals anything new. There is no un-revoke: a device that
was revoked pairs again with new keys.

**DECIDED HERE:** the closed `reason` list, and no un-revoke. Vectors: `revocations`, `revocation_op`.

### 6.3 Removing a device from one workspace

This is the bridge op `member_remove` (§8.7), `{"op": "member_remove", "device_id": hex}`, from a member
with the `operate` scope (spec §5.2). The host applies it as a rotation: a new epoch without that device.

### 6.4 Scoped agent devices (spec D15)

The owner's primary device issues an enrolment link
`v2.<person_id hex>.<space_id hex>.<code_id hex>.<code b64u>`, with a 32-byte `code`, one use and an
expiry. The agent generates its two keys and posts an `enroll_request` to the relay's person queue:

```
{"v":2, "suite", "kind":"enroll_request", "person_id", "space_id", "code_id", "dk_sig_pub", "dk_kx_pub",
 "mac": b64u(HMAC-SHA-256(code, "orch/v2/enroll|" || suite || space_id || lp16(dk_sig_pub) || lp16(dk_kx_pub)))}
```

The request is self-signed with `sig_enroll_request` as proof of possession. **The primary checks, in
order:**

1. the self-signature with the request's own `dk_sig_pub` → `bad_signature`;
2. the field set, and that `person_id` is its own → `malformed`;
3. the code is known → `unknown_code`, unused → `used`, and unexpired → `expired`;
4. the space and the MAC, compared in constant time → `bad_mac`.

It then marks the code used, and signs a certificate with `scopes_max = ["drop:<space_id>"]` and the
expiry it chose. A primary never makes a drop-scoped certificate any other way (§8.4). The relay enforces
the drop scope on every route. Vectors: `enroll` (valid then reused, expired, unknown code, a MAC over
other keys, a wrong self-signature, another space).

### 6.5 Recovery kit

The recovery kit (spec §5.2, D21) never crosses an orch protocol boundary except as an opaque blob that the
relay stores. **DECIDED HERE:** its format (the memory-hard KDF and its parameters) is deferred to P1 and
is not part of this contract.

## 7. Workspace card, member list, grants

### 7.1 The directory card

**P3-D4.** First publication is self-authenticating and session-less; later writes require
W(g). The same verified card is idempotent, including its signed cleartext and sealed hash.
A conflicting card at the same sequence remains `stale_card`. See §19.1 for quotas.

The card has two layers (spec §5.3):

- **A one-time delegation**, signed by the owner's `PK` once, when the workspace is created. It never
  changes.
- **The card itself**, signed by `WSK` alone. It changes on every `card_seq`, including each 90-day `WXK`
  rotation, without the owner's primary device.

```
delegation = {"o": {"v":2, "suite", "kind":"ws_delegation", "workspace_id", "wsk_pub", "owner_person_id",
                    "client_hosted": bool, "issued_ms"},
              "sig": b64u(Sign(PK_owner, "orch/v2/sig/ws-delegation|" || cj(o)))}

card = {"delegation": <delegation>,
        "o": {"v":2, "suite", "kind":"card", "workspace_id", "wsk_pub", "wxk_pub", "wxk_version",
              "owner_person_id", "relay_url", "card_seq", "issued_ms", "sealed_hash", "ck_commit"},
        "sig": b64u(Sign(WSK, "orch/v2/sig/card-wsk|" || cj(o))),
        "sealed": b64u(sealed part)}
```

**Why a delegation.** **DECIDED HERE.** The spec has both parts of the card signed by `WSK` and by `PK`.
Taken literally, every 90-day `WXK` rotation would need the owner's primary device online, and the host
could not rotate by itself (spec §5.4: "Rotation is automatic"). With the delegation, `PK` vouches once that
this `WSK` speaks for this workspace of this owner, and `WSK` signs everything that rotates.

**`client_hosted`** is in the clear (the relay learns that the workspace runs on someone else's machine).
The text "hosted by …" stays in the sealed part (spec D29).

**Showing the marker.** The sealed `hosted_by` is signed only by `WSK`, so a malicious client host could
publish `hosted_by: null`. Readers MUST therefore decide on the marker from the `PK`-signed delegation:

- **Readers MUST show the client-hosted marker whenever `delegation.client_hosted` is true.** The sealed
  `hosted_by` only supplies the name.
- If `hosted_by` is `null` (or empty) while the flag is true, readers show "hosted by (unknown)".
- If the flag is false but `hosted_by` names someone, readers show the marker with that name too. A host
  can only add the warning, never remove it.

Vector: `card.hosted_marker`.

**The sealed part:**

- It is `AES-256-GCM(HKDF(CK, "", "orch/v2/card|ws|card_seq"), zero nonce,
  cj({name, description, capabilities, hosted_by}), "orch/v2/card-aad|" || suite || ws || u32(card_seq))`.
- `CK` is fresh for every `card_seq` (so the zero nonce is safe), and sealed (purpose `card`) to every
  device the owner shares the card with.
- `sealed_hash = b64u(H(sealed))` puts the sealed part under the signature.
- `ck_commit = b64u(H("orch/v2/card-key-commit|" || workspace_id || u32(card_seq) || CK))`. A reader that
  unwrapped `CK` MUST check it against `ck_commit` before decrypting. Sealed wraps are not authenticated
  to their sender (§5.3), and AES-GCM is not key-committing, so without it a wrap could hand two readers two
  different `CK`s. **DECIDED HERE.**
- `hosted_by` is `null`, or the text shown as "hosted by …".

**`relay_url`** is `https://<lower-case host>[:port]` with no path and no trailing slash. For development
only, it may be `http://localhost`, `http://127.0.0.1` or `http://[::1]`, with an optional port.

**What the relay, orch-publish and peers check, in order:**

1. the field set, valid keys, the URL form, integers ≥ 1;
2. `owner_person_id == person_id(PK_owner)` → `other_person`;
3. the delegation: its signature with the account's `PK` → `bad_signature`; its field set → `malformed`;
4. the delegation's `workspace_id`, `wsk_pub` and `owner_person_id` equal the card's → `delegation_mismatch`;
5. the card's signature with `wsk_pub` → `bad_signature`;
6. `sealed_hash` against the sealed bytes → `bad_signature`.

**Update rules (relay).**

- `workspace_id` and `owner_person_id` never change (`other_workspace`).
- `wsk_pub` never changes (`wsk_changed`).
- The delegation never changes, byte for byte in its canonical form (`delegation_changed`).
- `card_seq` strictly increases (`stale_card`), except the same verified card is an idempotent retry
  (P3-D4).
- `wxk_version` stays the same with the same key, or rises by exactly 1 with a different key
  (`wxk_changed_without_version`, `bad_wxk_version`).

**DECIDED HERE:** the delegation and its labels; `sealed_hash`; `ck_commit`; `card_seq`; the URL form; and
the update rules. Vectors: `card.cases` (16, including a rotation signed by `WSK` alone, a delegation
signed by another person, a delegation for another `WSK`, and a changed delegation), and the round trip
`test_round_trip_card`.

### 7.2 Member list and epochs

**P3-D6 / D39.** A signed object, signed by `WSK` with `sig_member_list`:

```
{"v":2, "suite", "kind":"member_list", "workspace_id", "epoch", "list_seq", "issued_ms",
 "wk_commit",                                                  b64u, 32 bytes (G2b)
 "persons": [person_id, ...],                                  sorted, unique hex ids
 "members": [{"device_id": hex, "person_id": hex, "scopes": [...]}, ...]}          sorted by device_id, no duplicates

wk_commit = b64u(H("orch/v2/wk-commit|" || workspace_id || u32(epoch) || WK_epoch))
```

`list_seq` counts every list, and `epoch` counts keys. Adding a device does not change the epoch; removing
one does. **DECIDED HERE:** a separate `list_seq`, because the spec's `{epoch, members}` alone cannot
order two lists of one epoch.

**G2b (P3-D26): one `WK` per epoch, ever.** `wk_commit` has the form of `ck_commit` (§7.1) and is required.
Every list at one epoch carries the same `wk_commit`; the host never creates a second key for an epoch
number. A publication that is refused or abandoned after it left the host **burns** its `list_seq` and, if
it introduced a new epoch, that epoch: the next attempt uses a fresh key at a **higher** epoch. So `list_seq`
and epochs may have gaps. Epochs never fall. The epoch number stays the only key identifier (grants, the
bridge header, Drop `key_version`, push keys). `epoch` is a u32, `1 … 2^32−1`, everywhere it is parsed.

**What the relay checks before it accepts a list:**

1. the signature with the card's `wsk_pub`;
2. the shape: field set (including `wk_commit`, canonical b64u of exactly 32 bytes), sorted unique hex ids,
   `1 ≤ epoch ≤ 2^32−1`, `1 ≤ list_seq ≤ 2^53−1` (`malformed`);
3. `workspace_id` is the card's, **including on the first list** (`other_workspace`);
4. the first list has `1 ≤ epoch ≤ 2^16` and any valid `list_seq` (`bad_epoch`; G2b: a refused first
   publication burns `(1, 1)`, and the retry at `(2, 2)` is a valid first list); it must include a
   certificate-bound member device of the delegation owner (`other_person`), keeping the owner in `ever_persons`;
5. `list_seq` strictly increases (`stale_list`); gaps are allowed;
6. `previous.epoch ≤ epoch ≤ previous.epoch + 2^16` (`bad_epoch`). **Epochs may skip; they never fall.** The
   cap keeps a buggy host from exhausting the u32 space in one step;
7. if any previous member is missing, `epoch > previous.epoch` (`rotation_required`); a skip satisfies it;
7b. if `epoch == previous.epoch`, `wk_commit` equals the previous list's `wk_commit` (409 `wk_commit_changed`).
   There is no legacy exception: a stored list without `wk_commit` refuses every same-epoch list, and the host
   recovers by rotating to a higher epoch. Relay databases from before G2b are development data and MUST be wiped;
8. for every member:
   - not revoked (`revoked`);
   - a stored, valid, unexpired certificate whose person equals the entry's `person_id`, and is
     the card owner **or is in this list's `persons`** (`other_person`; P3-D6 / D39);
     the certificate verifies under that person's directory account key;
   - not a scoped agent, and `scopes` a prefix no longer than its `scopes_max` (`scope_exceeded`);
9. a WK grant is supplied for **every** member at this list's epoch in the same publication
   (`missing_grant`; P3-D7).

**Order (normative).** Checks 1–7b run before any grant is looked at; then the grants (shape, `other_workspace`,
`not_for_this_device`, `grant_conflict`); then checks 8 and 9 per member in list order (certificate, then that
member's grant). So a host that regenerated a key at the held epoch and re-sealed its grants gets
`wk_commit_changed`, not `grant_conflict`, and the same body at the held `list_seq` gets `stale_list` (vectors
`p3.resealed_same_epoch_wk_commit_changed_before_grant_conflict`,
`p3.resealed_same_list_seq_stale_list_before_grant_conflict`).

**What the relay cannot check (G2b).** Grants are sealed, so the relay cannot compare a grant's `WK` with
`wk_commit`. Its part is the field's presence and shape, the epoch ranges, and same-epoch consistency (7b).
Devices check every grant they use against the list's `wk_commit` (§7.3 D3, D4).

**P3-D6.** `persons` is a WSK-signed authorization statement, not proof of F1 roles. A WSK
holder can add a foreign person (and can already leak WK). In P3 lists have one person in practice.
Devices verify signed snapshots and persist increasing `list_seq` and non-decreasing epochs; they
need not see every intermediate list, so may accept forward epoch jumps of any size. The
`2^16` window above is for relay publication. Restricted tickets are deferred to P8 (P3-D14); P3 hosts refuse `not_visible`.
F1's existing signature context, `roster_v`, `grant.issued` and `auth` supersede #24's older
`list_seq`, session-grant and `presence` event proposal (P3 design §7).

**P3-D7.** The publication body is exactly `{member_list, grants: [wk_grant],
card_key_wraps?: {card_seq, wraps: [{device_id, sealed}]}}`. It is an authenticated HTTP
container, **not another signed kind**: the list and each grant carry their existing signatures.
All grants must name this workspace, this epoch and a member of this list; no duplicate devices.
Wrap devices are unique current-list members and `card_seq` equals the current card. Sealed
values use §5.3. The relay cannot check their plaintext. Limits: 1,024 members, 2 MiB whole body.
The relay checks all signatures and certificates against the proposed list's `persons`, including
new people, and commits the list, grants and wraps together or changes nothing. Different bytes
for an existing `(device, epoch)` grant are `grant_conflict`. An exact-body retry returns its
committed result before freshness checks, after session and holder authorization. Hosts persist
the key and sealed publication bytes before sending; they resend those bytes, never reseal.
There is no rotation-abandon route or label: a refused publication is abandoned by the host alone,
which burns its epoch and `list_seq` (H4 below). Lost keys after commit require the next rotation.

On acceptance, the relay deletes mailboxes, queued responses, grants and card-key wraps of departed
devices (P3-D7; push subscriptions from P4).
Vectors: `member_lists`.

**Host rules (spec §5.4).**

- **When it rotates.** The host rotates at startup and once a day:
  - if the epoch is 90 days old;
  - on a revocation it learns of;
  - on a removal;
  - on `orch keys rotate`.
- **How it rotates:**
  1. generate and durably persist `WK_E` at the next unused epoch `E = EHW + 1` (H1, H2; P3-D7). Epochs may
     skip, never fall;
  2. seal and persist a grant for every remaining device, and sign the list with `wk_commit` for `WK_E`;
  3. publish the list, grants and optional card-key wraps atomically;
  4. seal everything new under `E` once the relay has accepted that list (2xx). After a revocation or removal
     the rotation gate is up from the decision on, and nothing new is sealed under the old epoch in between.
- **What it keeps.** It keeps every old `WK` to read old content, and every burned `WK` (H4). It never seals new
  content under an old epoch (§8.5).
- **New devices (spec D26).** A device that joins at epoch `e` is granted `WK_e` and later epochs only.

**Publication host rules (G2b, P3-D26; orch-core host §11, orch-core #382).** A publication body is **exposed**
from the moment its first send starts. After that the host never assumes it was not stored: a hostile relay can
store and serve a body it reports as refused.

- **H1, durable allocation.** In the same durable store as `WSK`, the host keeps `LHW` (the highest `list_seq`
  ever signed, not the committed one), `EHW` (the highest epoch it ever generated a key for) and, per epoch, the
  **holder set**: every device sent a grant for that epoch in any exposed body. Exactly one writer: the fenced
  holder. `list_seq` is never derived from `roster_v` or the log.
- **H2, write-ahead.** Before the first send it persists atomically the signed list, grants and body bytes,
  `LHW := list_seq`, for a new epoch `WK_E` and `EHW := E`, and the holder-set additions. At most one body is
  exposed at a time.
- **H3, outcomes.**
  - 2xx: install it; activate `WK_E`.
  - **Transient** (lost response, connection error, timeout, 5xx, 429, 401 `unauthenticated`/`expired` then
    re-login, `fenced` then an explicit re-hold): resend the **exact bytes**. After a re-login or a re-hold the
    host first does `GET members`; if the verified list is above `LHW`/`EHW`, or is not a body it exposed, H7.
  - **Container-only** (`stale_card`, `wrap_conflict`): resend the **same signed list and grants** with corrected
    or omitted `card_key_wraps`. Nothing is burned; devices see an identical `cj(o)`.
  - **Content** (`revoked`, `cert_expired`, `cert_invalid`, `other_person`, `scope_exceeded`, `malformed`,
    `bad_signature`, `other_workspace`, `missing_grant`, `not_for_this_device`) or **divergence** (`stale_list`,
    `bad_epoch`, `rotation_required`, `grant_conflict`, `wk_commit_changed`), or any decision to change the list
    while a body is exposed: **abandon** the body (H4).
- **H4, abandoning burns.** The abandoned `list_seq` is never signed again; the next list uses `LHW + 1`. If the
  body introduced an epoch `E` above the committed one, `E` is **burned**: every later list has an epoch above
  `E` (a list that needs no rotation still rotates to `EHW + 1`), and the next key is generated at `EHW + 1`.
  The host stops sending the old body before it persists the burn, never resends a burned body, and does not
  adopt a burned body the relay later shows as committed. **A burned `WK_E` is kept like an old epoch key**
  and deleted under the same retention. It is never activated. Under it the host only opens requests to answer
  the §8.5 `stale_epoch`. **It never seals anything else under it**: no data response, no `drop_rewrap` output,
  no other content. **There is never a second key for an epoch, and the host never reseals at a refused epoch.**
- **H5, holder rule.** A list at epoch `E` includes every device in `E`'s holder set; otherwise the next list
  uses a new epoch. The rotation gate (no new sealing under `E`) goes up as soon as the host decides to drop
  such a device. Example: a same-epoch addition of X refused `revoked` or `cert_*` means X may hold the
  committed `WK_e` through the relay, so the host rotates as for a revoked member (§6.2).
- **H6, one list per `list_seq`.** The host never signs two different `cj(o)` under one `list_seq`. It never
  re-signs; it resends persisted bytes.
- **H7, host-state loss** (backup restore, disk loss, a missing or torn store while the `WSK` exists, the
  relay's verified list above `LHW`/`EHW` or with content the host never exposed, no local `WK` for the relay's
  committed epoch, or a takeover by an instance without the latest store): `GET members` and verify it with the
  `WSK`; set `LHW := max(local, relay list_seq) + 1024` and `EHW := max(local, relay epoch) + 1024`; rotate at
  once to `EHW + 1`.
- **The clamp (liveness limit).** The rotation target is `min(EHW + 1, committed + 2^16)`, and **the clamp wins**:
  the relay refuses anything above `committed + 2^16` (check 6), and every epoch up to `EHW` is already allocated,
  so a target below `EHW + 1` is never usable (it would be a second key for a burned epoch). When
  `EHW + 1 > committed + 2^16` the host does not rotate: it alarms and keeps the rotation gate up, and the workspace
  is frozen for new sealing until an operator intervenes (for example a fresh workspace). Reaching it takes about
  65,000 burns, or about 63 H7 jumps of 1024 with no commit in between.
- **H8, refusal alarms** (the orch-52 / #382 definition). The host counts the **content and divergence**
  refusals of H3 only; transient outcomes neither count nor back off. The count resets on a 2xx. After **3
  consecutive** counted refusals it raises an operator alarm (`host.status`) and backs off exponentially between
  attempts, capped at 5 minutes; each attempt burns at most one epoch, so the u32 space lasts for centuries.
  Separately it alarms when **a rotation stays uncommitted for 10 minutes** for any reason, transient errors
  included (a hostile relay can answer 5xx forever). Backoff never lowers the rotation gate.

**DECIDED HERE (G2b):** burned epochs instead of a second key per epoch or explicit key ids; the `2^16`
first-list and skip window; `wk_commit` with the relay check `wk_commit_changed` as defence in depth.
Vectors: `member_lists` (34 cases), `wk_commit`, the host-conformance list in orch-core host §11.

### 7.3 WK grants

```
{"o": {"v":2, "suite", "kind":"wk_grant", "workspace_id", "device_id", "epoch",
       "sealed": b64u(seal_to(device dk_kx, purpose "wk", object = workspace_id, epoch, WK_e))},
 "sig": b64u(Sign(WSK, "orch/v2/sig/wk-grant|" || cj(o)))}
```

- **The grant is signed.** **DECIDED HERE.** Without a signature, the relay could seal a `WK` of its own to
  the device, which would then send requests the relay can read. A device MUST verify the grant with the
  `WSK` it pinned at pairing before it uses the key.
- **Where it lives.** The relay stores grants per `(workspace, device, epoch)`. Devices fetch them at
  connect, and whenever they get a `stale_epoch` refusal (§8.5).
- **The device's current epoch never moves backwards.** A device MUST persist the highest epoch for which
  it holds a verified grant, per workspace, and use that one. An older grant is kept only to read older
  content. **DECIDED HERE.**

An SK grant (shared Drop spaces) is the same, with `kind: "sk_grant"`, `space_id` in place of
`workspace_id`, purpose `sk`, and signed by the space owner's key (`WSK`, or the owning device's `dk_sig`).
Vectors: `wk_grants`.

**P3-D8.** A current epoch is confirmed by a verified member list as well as its signed grant;
an unsigned HTTP hint never raises a device's epoch.

**Device rules (G2b, P3-D26).** Vectors: `member_list_snapshots`.

- **D1, persisted head.** Per workspace, a device persists atomically the highest verified list's
  `(list_seq, epoch, H(cj(o)), wk_commit)`, and the `wk_commit` of every epoch it has seen in a verified list.
- **D2, snapshot acceptance.** First contact takes any `epoch ≥ 1` and `list_seq ≥ 1`. A lower `list_seq` is
  refused and not adopted (`stale_list`). The same `list_seq` with the same `cj(o)` is a no-op: **the signature
  bytes are never compared**, so a high-s twin is not a conflict. The same `list_seq` with another `cj(o)`
  raises `conflicting_snapshot`. An epoch below the head's is refused (`bad_epoch`), and so is a removal without
  a higher epoch (`rotation_required`). **New:** two verified lists at one epoch with different `wk_commit` raise
  the local alarm `wk_commit_conflict`; the device stops sealing at that epoch until a verified list at a
  **higher** epoch arrives. The alarm is checked **before** the `stale_list` refusal: a lower `list_seq` at a known
  epoch with another `wk_commit` is WSK-signed proof of two keys at one epoch, so it raises `wk_commit_conflict`
  (vector `lower_list_seq_other_wk_commit_alarm`). A list at the head's own `list_seq` with other content raises
  `conflicting_snapshot` even if its `wk_commit` differs too, and that alarm does **not** block sealing: D3's
  grant/commit match against the head still keeps the device off the other key (vector
  `same_list_seq_other_wk_commit_conflicting_snapshot_no_block`).
- **D3, sealing key.** The device seals and sends only under `head.epoch`, with a WSK-verified grant whose
  unsealed `WK` matches `head.wk_commit`. A grant that does not match is discarded for sealing. If none matches,
  **sending is blocked** (`no_key`): the device refetches grants and never falls back to an older epoch.
- **D4, reading.** For the head epoch or an older one, any WSK-verified grant for that epoch opens content; if
  the device holds a verified list for that epoch, the key must match its `wk_commit` (otherwise
  `wk_commit_mismatch`). A device that jumped epochs keeps reading old content. An epoch above the head (or any
  epoch before a first verified list) is refused locally (`future_epoch`): epochs move only per D5.
- **D5, epoch moves** are unchanged: only on a verified list, or on a verified host `stale_epoch` naming a higher
  epoch, after which the device demands a list at `≥` that epoch. If bounded refetches bring nothing, it shows
  "relay is withholding the new key", not a timeout.
- **D6, Drop repair (MAY, deferrable).** When the device moves off an epoch `E` and the relay has no grant at `E`
  for it (404), `E` was probably burned. The device **re-wraps its own Drop objects** that it wrapped under `E`,
  at the current epoch. The host does **not** serve `drop_rewrap` under a burned key (H4): under it, it answers
  only `stale_epoch`. Wrong answers from a hostile relay only cost an extra re-wrap.

### 7.4 WXK rotation (spec D27)

`WXK` rotates with the 90-day epoch. The new card carries `wxk_version + 1`.

- The host records `retired_ms`, the moment the old key stopped being current. It keeps the old private
  key, and accepts envelopes and wraps sealed to it, while `now < retired_ms + 14 days`. Then it deletes it.
- Senders take `wxk_version` from the card. On `stale_wxk` (§11.5), they refetch the card and reseal.
- **The resealed envelope MUST get a new `id`**, and a new `sent` entry (the old entry is dropped). The
  receiver keeps the refused envelope's outcome under `(from_ws, id)`, so the same id with other bytes is an
  `id_conflict` and is dropped (§11.4). Vector `reseal_after_stale_wxk_needs_a_new_id`.

Vectors: `ws_envelopes.previous_wxk_inside_14_days`, `previous_wxk_after_14_days`.

### 7.5 Re-wrapping old objects for a new device (spec D26)

A device asks with the bridge op `{"op": "drop_rewrap", "object_id", "version"}`. The host:

1. checks that the device's scope allows reading the object;
2. opens the object's `wk` wrap of the old epoch;
3. uploads a new `wk` wrap under the current epoch (§10.3), over its workspace session.

## 8. Bridge v2

### 8.1 Envelope and header

```
envelope = header (108) || ciphertext || tag (16) || signature (64)          overhead 188 bytes
```

The size limits are v1's: a request is at most 1 MiB decoded, a response chunk at most 256 KiB, and meta
at most 64 KiB.

| Offset | Size | Field | Request (to host) | Response chunk (to device) |
|---|---|---|---|---|
| 0 | 4 | magic | `"ORB2"` | `"ORB2"` |
| 4 | 1 | version | 2 | 2 |
| 5 | 1 | direction | 1 | 2 |
| 6 | 1 | flags | only `STREAM` 0x02 | `LAST` 0x01, `STREAM` 0x02, `REFUSAL` 0x04 (REFUSAL requires LAST) |
| 7 | 1 | suite | the deployment's suite | same |
| 8 | 16 | workspace | workspace_id | same |
| 24 | 16 | device | the sender's device_id | the device the response is for |
| 40 | 16 | rid | request id = the mailbox id | the request's rid |
| 56 | 16 | stream | the stream acted on, or zeros; **at epoch 0: the offer_id** | the stream's rid for frames, else zeros; at epoch 0, the offer_id |
| 72 | 8 | seq | device sequence number, from 1 | chunk index, from 0 |
| 80 | 8 | ts_ms | sender clock (+ offset) | host clock |
| 88 | 4 | epoch | `WK` epoch, or 0 for pairing | the request's epoch |
| 92 | 16 | salt | 16 CSPRNG bytes | 16 CSPRNG bytes |

The whole header is the AAD and is signed. **DECIDED HERE:**

- the new magic `"ORB2"`, so a v1 parser fails at once (vector `old_magic_v1_dropped`);
- `key_version` is replaced by `suite`;
- `epoch` is a `u32` placed before the salt;
- the offer id travels in `stream` at epoch 0.

### 8.2 Keys, sealing and signing

```
channel key  = K_bridge(e) = HKDF(WK_e, "", "orch/v2/bridge|" || hex(ws) || "|" || dec(e))      epoch e ≥ 1
             = K_pair      = HKDF(S,    "", "orch/v2/pair|"   || hex(ws) || "|" || hex(offer))  epoch 0
K_msg        = HKDF(channel key, salt = header.salt, "orch/v2/bridge-msg")
body         = AES-256-GCM(K_msg, 12 zero bytes, plaintext, AAD = header)
signature    = Sign(signer, "orch/v2/sig/bridge|" || header || body)
plaintext    = u32(meta_len) || cj(meta) || data                     (meta_len ≤ 65,536)
```

- **Signers.** Requests are signed by the device's `dk_sig`, as named by its certificate. Responses are
  signed by `WSK`. At epoch 0, the pairing request is signed by the new `dk_sig` as proof of possession.
- **Who can read.** Only member devices holding `WK_e` can read epoch-`e` traffic, which is v1's open
  problem D1 solved by spec D2. At epoch 0, only holders of the link can read.

Vectors: `bridge.seal`, `hkdf` (`k_bridge_epoch_1`, `k_bridge_epoch_2`, `k_pair`, `k_msg_bridge`).

### 8.3 Pairing v2 (spec §7, D6)

1. **Link.** The host's Remote tab shows, as a QR code (10 minutes, single use):

   ```
   https://<relay>/pair#v2.<workspace_id hex>.<offer_id hex>.<b64u S>.<b64u wsk_pin>.<b64u pk_pin>
   ```

   **D45/D46 (P3 design §7).** The native link is also
   `orch://pair?relay=<percent-encoded relay origin>#v2.<the same five fields>`.
   `/app/pair` remains an HTTPS alias. Passkey registration is removed from native pairing;
   the exact checkpoint baseline is `{n, hash}`, or null only when none exists; see §19.8 (P3-D13/D20).

   The spec's link has four fields after `v2`. **DECIDED HERE:** a fifth, `pk_pin`, because spec §7 step 4
   says the QR carries a pin of the owner's `PK`. The phone parses the link strictly (vectors
   `bridge.links`):
   - exactly `v2`;
   - lower-case hex ids;
   - canonical 43-character b64u of 32 bytes for each of the last three fields.

   The fragment never reaches a server. The host creates the offer with `S`, `sas_nonce` (32 bytes) and the
   scope.

   **Every answer to an epoch-0 request carries `wsk_pub`:** each `pair_status` state and every refusal.
   The device checks it against the link's pin before it reads anything else (step 4).

2. **Pair request** (epoch 0, sealed under `K_pair`, header `stream` = `offer_id`, signed by the new
   `dk_sig`; the header `device` is `device_id(dk_sig_pub)`):

   ```
   meta = {"op":"pair", "dk_sig_pub", "dk_kx_pub", "label": text, "cert": null | <signed device_cert>}
   ```

   - The field set is exact.
   - A phone that is already one of the owner's devices sends its certificate. If the certificate's
     person differs from `pk_pin`, the phone shows "this workspace belongs to someone else" and sends
     nothing.
   - **DECIDED HERE:** there is no MAC. The AEAD tag under `K_pair` already proves knowledge of `S`, and
     unlike v1's `K_ws`, nobody else holds that key.

3. **Host checks**, in this order, after §8.6 steps 1–3, which give silence for an unknown offer or a bad
   tag:
   1. the meta shape → `malformed`;
   2. the offer is open and unused. A resend by the device that holds the pending pairing, with the same
      two keys, is answered `pending` again. Otherwise → `pairing_closed`;
   3. `device_id(dk_sig_pub)` equals the header's, and the signature verifies → `bad_signature`;
   4. the time window → `stale_timestamp` (`host_ms`);
   5. if `cert` is present:
      - its person is the card owner → `other_person`;
      - it is valid → `cert_invalid`, `cert_expired` or `revoked`;
      - it is for these two keys → `cert_invalid`.

   Every refusal counts against the offer's own budget (5 per minute) and **carries `wsk_pub`**. The host
   then marks the offer used, records the cleaned label, and answers:

   ```
   {"state":"pending", "wsk_pub", "sas_nonce", "dk_sig_pub", "dk_kx_pub"}          exactly these five
   ```

4. **The device checks every answer to an epoch-0 request** (vectors `bridge.pair_answers`), in this
   order:
   1. the shape, with `epoch = 0` and `stream = offer`;
   2. a pending rid;
   3. the tag under `K_pair`;
   4. `wsk_pin(wsk_pub) == link pin`;
   5. the signature with that `wsk_pub`;
   6. the chunk order;
   7. the window, **for every answer, refusals included**. The one exception: a verified `stale_timestamp`
      refusal is exempt from the window and adopts its clock once per pending rid, within 24 h (v1 §5.1).
      Vector `refusal_outside_the_window`.

   For `pending`, the echoed `dk_sig_pub`/`dk_kx_pub` MUST be its own. Otherwise the device drops the
   answer and **raises the alarm** (`not_my_key`): someone is pairing another key with this link. It then
   shows `sas(...)` (§4) and pins `wsk_pub`. No answer within 60 s, or `pairing_closed`, shows v1's "this
   link was used by someone else: reject it on your Mac".

5. **Human confirmation on the host.** The default is Reject. Approve becomes available once the owner has
   compared the code on both screens.
   - If the phone sent a valid certificate, or the host *is* the owner's primary device (it signs
     locally), the host goes on to step 6.
   - Otherwise it enters **`cert_pending`** (§8.4).
   - **No `WK` is sealed before a valid certificate exists** (spec §7).

6. **Approval.** The host:
   1. uploads the certificate to the directory, if new;
   2. uploads a WK grant for the current epoch;
   3. publishes the new member list;
   4. completes native pairing; no platform passkey registration (D45/D46, P3 design §7).

The device polls with `{"op":"pair_status"}` (epoch 0, signed with its new key, read-only). Answers are
exactly one of:

```
{"state":"pending", "wsk_pub", "sas_nonce", "dk_sig_pub", "dk_kx_pub"}     the same five fields as step 3
{"state":"cert_pending", "primary_label": text, "pk_pub": b64u, "challenge": <signed cert_challenge> | null,
 "wsk_pub"}
{"state":"approved", "scopes": [...], "cert": <signed device_cert>, "pk_pub": b64u, "epoch": e, "wsk_pub"}
{"state":"rejected", "wsk_pub"}
{"state":"expired", "wsk_pub"}            cert_pending ran 10 minutes without a certificate
```

`pending` repeats the full five-field answer, with the key echo, so a device whose first answer was lost can
still check the echo and show the code. A device ignores fields it does not know.

On `cert_pending`, the device checks `pk_pin(pk_pub)` against the link. If `challenge` is not `null`, it
checks the challenge as §8.4 says and shows its `cert_code`.

On `approved`, the device checks:

- `pk_pin(pk_pub)` against the link;
- the certificate's signature, its two keys (they must be its own) and its validity;
- `scopes`.

It then logs in to the relay (§12.2) and fetches its WK grant (§7.3). **DECIDED HERE:** the answer shapes,
the `expired` state, that every answer carries `wsk_pub`, and that `approved` carries `pk_pub` and the
certificate. Vectors: `host_cases` `pair_*`, `pair_status_*`, `pair_answers`, and the round trip
`test_round_trip_pairing_through_cert_pending`.

### 8.4 `cert_pending`: the request to the primary device and its challenge

A first-time phone needs a certificate from the owner's primary device. The host cannot make one, and a
host must not be able to get one for a key of its choosing. The flow is:

1. **The host's request.** The host posts a `cert_request` to the relay's queue for
   `(person_id, primary_device_id)`:

   ```
   {"o": {"v":2, "suite", "kind":"cert_request", "request_id", "workspace_id", "person_id", "primary_device_id",
          "created_ms", "expires_ms" (= created + 10 min),
          "sealed": b64u(seal_to(primary dk_kx, "cert-request", object = request_id, epoch 0, cj(inner)))},
    "sig": b64u(Sign(WSK, "orch/v2/sig/cert-request|" || cj(o)))}
   inner = {"device_id", "dk_sig_pub", "dk_kx_pub", "label", "scopes_max", "offer_id"}       exactly these
   ```

   `inner` carries **no host nonce**. Anything the host chooses could be ground against a 30-bit code.

2. **The primary checks, in order:**
   1. the card is its own person's → `other_person`;
   2. `sig` against the card's `WSK` (the card's delegation already verified) → `bad_signature`;
   3. it is the addressee, for its own person → `not_for_this_device`;
   4. `created − 300 s ≤ now < expires`, with `expires − created ≤ 10 min` → `expired`;
   5. the `request_id` was never seen before → `replayed`;
   6. no other request of this workspace is open → `request_open` (at most one open request per
      workspace). **A request is open while it is unexpired and neither signed nor rejected**, so an
      expired or rejected request never blocks the workspace;
   7. the inner field set is exact, the keys are valid, `device_id` derives from `dk_sig_pub`, and the
      scopes are valid → `malformed`;
   8. `scopes_max` is not a `drop:` scope → `scope_exceeded` (scoped agents enrol only through §6.4).

   If the card's delegation says `client_hosted`, the primary goes on, but shows a **warning**: "this
   workspace runs on a machine that someone else administers".

3. **The primary's challenge.** The primary now draws `primary_nonce`, 32 CSPRNG bytes, **after** the keys
   reached it. It keeps the challenge as the only thing it will ever certify for this request, and posts it
   to the relay's queue for `(workspace_id, request_id)`:

   ```
   {"o": {"v":2, "suite", "kind":"cert_challenge", "request_id", "workspace_id", "person_id", "device_id",
          "dk_sig_pub", "dk_kx_pub", "primary_nonce", "expires_ms" (= the request's)},
    "sig": b64u(Sign(PK, "orch/v2/sig/cert-challenge|" || cj(o)))}
   cert_code = base32(H("orch/v2/sas-cert|" || suite || cj(challenge.o)))[0:6]
   ```

   The primary shows `cert_code` with the label and asks for a confirmation.

4. **The host relays the challenge** unchanged, in its `cert_pending` answer (§8.3). Until it arrives,
   `challenge` is `null`, and both screens say "Open orch on <primary>".

5. **The phone checks the challenge** before it shows anything:
   1. `pk_pin(pk_pub)` against the link;
   2. the signature with that `pk_pub`, and the exact field set → `challenge_signature`;
   3. `workspace_id` is the link's, and `person_id` is `person_id(pk_pub)` → `not_for_this_workspace`;
   4. `device_id`, `dk_sig_pub` and `dk_kx_pub` are **its own** → otherwise drop and **raise the alarm**
      (`not_my_key`): someone asked the primary to certify another key for this pairing;
   5. `now < expires_ms` → `challenge_expired`.

   Then it shows `cert_code`.

6. **The human compares the code on the primary and the phone, and confirms on the primary.**
   - The primary signs a certificate (§6.1) **for exactly the two keys of its own stored challenge**, once
     per request (`already_signed` afterwards), and uploads it to the directory. It signs only while the
     challenge is unexpired (`expired`) and not rejected (`rejected`).
   - A human who rejects on the primary closes the request; nothing is ever signed for it.
   - The host polls the directory for the certificate, then continues with §8.3 step 6.

**UI rules for the two codes (R8).** The phone shows two codes in turn. To keep them apart:

- When `cert_pending` begins, the phone **clears the first (pairing) code** from its screen.
- It labels `cert_code` "compare with <primary>", using `primary_label`.
- It **stops showing `cert_code` after the challenge's `expires_ms`**.
- The primary shows `cert_code` under the same label, and the phone's label.

**Why this closes R1.** **DECIDED HERE:** the challenge. The host never chooses anything the code depends
on. `PK` signs the keys, and the nonce is drawn after the keys are fixed. Only the primary holds `PK`, so the
host cannot forge a challenge for the phone's keys.

A host that sends the primary a request for a key of its own gets a challenge that names that key. The
honest phone refuses that challenge with the alarm, so it shows no code, and the human has nothing to
match. The primary allows one open request per workspace, so the host cannot run a second request beside
the honest one.

This replaces the first draft's rule that a client-hosted workspace may not ask for a certificate; that
rule is now a warning.

**What the spec said.** Spec §7 says the primary shows "the same fingerprint" as the host step. With this
fix it shows the challenge's code instead, which the phone also shows. The owner accepted this in review.

Vectors: `cert_request.cases` (valid; expired; signed by another workspace; client-hosted with a warning;
not for this device; the card of another person; a drop scope; a replayed request id; a second open
request; an inner object with a host nonce), `cert_request.open_cases` (the next request after one expired
or was rejected, signing after a rejection or after expiry), `cert_request.challenge`, `cert_code`, `signed_cert`,
`sign_again`, `attack_challenge`, and `pair_answers` (`cert_pending_with_the_primarys_challenge_shows_its_code`,
`r1_attack_challenge_for_another_key_raises_the_alarm`, `challenge_signed_by_the_host_not_pk`,
`challenge_for_another_workspace`, `challenge_expired`, `cert_pending_with_a_pk_not_of_the_pin`). Round
trips: `test_round_trip_pairing_through_cert_pending`, `test_round_trip_r1_attack_fails`.

**P3-D11.** Queue routes are in §19. The primary uses a device session of the addressee,
including for a challenge or rejection. A rejection is exactly:

```
{"o": {"v":2, "suite", "kind":"cert_rejection", "request_id", "workspace_id", "person_id"},
 "sig": b64u(Sign(PK, "orch/v2/sig/cert-rejection|" || cj(o)))}
```

The relay verifies requests under the card's WSK and challenges/rejections under the account PK.
Identifiers must match the stored request; a challenge has the request's expiry, valid device keys
and the derived device id. The state machine is `open → challenged → signed`, with `rejected`
from open or challenged, and `expired` from either at `expires_ms`. Challenges cannot be replaced:
(G0a review 3) a valid signature over identical `cj(o)` is idempotent (200, no state change),
including re-signed challenges and rejections; different canonical challenge content is `replayed`. Rejection after signing is `already_signed`;
challenge or certificate completion after rejection is `replayed`. Verified canonical terminal retries are
idempotent while the record is retained. Expired non-terminal requests return 410 `expired`.
The request becomes signed only when a stored, valid certificate matches **both keys**, device and
person of its challenge. An unrelated certificate can be stored but cannot complete the request.
Scopes are sealed: the host checks them. Terminal records remain until `expires_ms + 60 s`.

### 8.5 Epochs on the bridge

- A request MUST use the host's current epoch.
  - A request at a **lower** epoch whose key the host still holds: after its signature verifies, it is
    recorded and refused `stale_epoch` with `"epoch": current`. The refusal is sealed under the
    request's own (old) epoch, so the device can read it. It contains nothing else.
  - A request at a **higher** epoch, or at an epoch whose key the host deleted, is dropped: there is no key
    to open it with.
  - (G2b) A **burned** epoch's key (§7.2 H4) counts as held. A phone pinned to a burned epoch by a withholding
    relay gets the host-signed `stale_epoch` sealed under that key, and nothing else is ever sealed under it.
- **The device** answers `stale_epoch` by fetching its grant and sending the request again as a new
  request (new rid, new seq). The refused seq is consumed (vector
  `stale_epoch_consumes_its_seq_then_a_new_request_runs`).
- A device MUST drop a `stale_epoch` refusal whose `epoch` is not higher than its request's epoch
  (vector `stale_epoch_refusal_not_higher_than_the_request`). Its current epoch never moves backwards
  (§7.3).
- A response chunk MUST carry the epoch of its request. The device drops anything else
  (`response_in_another_epoch_than_the_request`).
- **On rotation, the host:**
  - ends every open stream with `LAST | REFUSAL` `stale_epoch`;
  - answers a request that ran but has not finished sending with `already_done` / `status: "unknown"`,
    instead of more data under the old epoch.

  **DECIDED HERE:** no new data is ever sealed under an epoch that a revoked device may hold.

Vectors: `previous_epoch_refused_stale_epoch`, `future_epoch_dropped`,
`epoch_whose_key_the_host_deleted_dropped`, `sealed_under_another_epochs_key_dropped`, device
`stale_epoch_refusal`.

### 8.6 What the host does with a request (normative order)

This is v1 §6.1, with the v2 changes in bold. The rule is unchanged: **silence for anything a party without
the channel key could have produced, and a sealed, host-signed refusal for everything after the tag
verified.**

1. **Shape.** Drop on any of:
   - a size outside 188 … 1 MiB;
   - a magic other than `"ORB2"` or a version other than 2;
   - direction ≠ 1, or a flag other than `STREAM`;
   - **a suite ≠ the deployment's**;
   - another workspace;
   - a mailbox id ≠ rid.
2. **Key.** **Epoch > current: drop. Epoch 0: the offer named by `stream`, otherwise drop. Otherwise
   `WK_epoch`, otherwise drop.**
3. **Tag.** Drop on failure. **At epoch 0, go to §8.3.**
4. **Device.** Each of these is a refusal within the host-wide budget (10 per minute), and is dropped
   once the budget is spent:
   - revoked → `revoked`;
   - **not in the current member list → `not_member`**;
   - signature (with the certificate's `dk_sig_pub`) → `bad_signature`.
5. **Replay.** A known rid gets v1 §5.3's answer, with these v2 changes (P3-D27):
   - **An answer that was posted to the relay is replayed as the exact chunk bytes already posted**, never
     re-sealed or re-stamped: the relay refuses other bytes at a known chunk index (`chunk_conflict`). The
     host persists each response envelope's exact bytes with the rid record **before the first POST**,
     including a POST whose outcome was uncertain (a timeout may still have been accepted). The relay
     stores an identical chunk again after its copy expired, bounded (§19.3).
   - v1's re-seal and re-stamp apply only to an answer none of whose chunks was ever posted; such a
     re-sent stored `stale_epoch` carries the current epoch.
   - **A resend of a known rid whose op is still running gets no answer.** No interim
     `already_done {status: "unknown"}`: it would take idx 0, and the real answer would then be refused
     with `chunk_conflict`. The answer is posted once, when the op finishes. `already_done {unknown}`
     stays for a record without an outcome whose op is not running (after a crash).

   5b. **Quota.** v1 §5.3 unchanged (`busy`; drop past the allowance or `MAX_RECORDS`).
6. **Framing.** Strict meta (§2.3), with `op` a string. Otherwise record, then refuse `malformed`; the seq
   is not consumed.
7. **Sequence.** The v1 window → `stale_sequence` (`high`). It is consumed from here on.
8. **Time.** ±300 s → `stale_timestamp` (`host_ms`).
9. **Epoch.** **≠ current → `stale_epoch` (`epoch`).**
10. **Stream.** Another device's stream → `forbidden_scope`.
11. **Record and run.** Then the route scope against the member's `scopes`, the assertion requirement
    (v1 §9), and the op.

Every refusal after step 4 is recorded before it is sent (v1 §5.3). Vectors: `bridge.host_cases`
(47 per suite, including chains).

### 8.7 Ops, meta and WebAuthn

**D45/D46 (P3 design §7).** Native clients do not use the WebAuthn ops below. Their replacement
is deferred with Type (mobile D-5); the historical vectors remain test-only.

**Request ops.** These are v1's, plus five:

- v1's: `http`, `cancel`, `pair`, `pair_status`, `credential_begin`, `credential_finish`, `assert`;
- `member_remove` (§6.3);
- `revocation` (§6.2);
- `drop_rewrap` (§7.5);
- `decision` (§13);
- `new_ticket`: a sealed request the host applies (spec §7). Its fields are the host's ticket API
  (follow-up F3).

**Response meta.** It is v1 §3.5's, and a refusal carries only its code and documented fields (§14).

**WebAuthn.** This is v1 §9 with only the challenges changed:

```
assert challenge = H("orch/v2/assert|" || ws || device_id || rid || u32(epoch) || u8(purpose) || u8(scope)
                     || u64(expires_ms) || nonce (32) || H(cj(subject)))
registration     = H("orch/v2/webauthn-reg|" || ws || device_id || u64(expires_ms) || nonce (32))
```

The RP id and origin are the relay origin that serves `/app`. **DECIDED HERE:** `epoch` is in the
assertion challenge, so an assertion cannot be carried across a rotation. Vectors: `webauthn`.

### 8.8 What the device does with a response chunk

This is v1 §7, with the v2 changes in bold. Drop unless, in order:

1. the size is within 188 … 256 KiB;
2. magic, version 2, direction 2 and the flags are valid;
3. **the suite**, workspace and device are its own;
4. the rid is pending;
5. **the epoch equals the request's**;
6. the mailbox fields match;
7. **`WSK`** verifies the signature;
8. the tag verifies;
9. seq is the next index;
10. the window holds, with the `stale_timestamp` exception.

The pin-failure counting and "pair again" after 3 failures are v1's. A `stale_epoch` refusal with a higher
epoch makes the device fetch grants (`fetch_grants`); any other is dropped (§8.5). Vectors:
`bridge.device_cases`.

**Replayed answers (P3-D27).** A host replays exact posted bytes (§8.6 step 5), so a replayed chunk keeps
its original `ts_ms`, `host_ms` and `high`:
- The phone's last automatic resend of a rid should start no later than about 240 s after its **first**
  send, so that a replayed answer is likely to pass step 10's ±300 s window. This is best-effort, not a
  guarantee: acceptance also depends on the clock offset and on how long the host took before stamping the
  original answer's `ts_ms`. A replay outside the window is dropped, and the device ends `uncertain`, the
  defined outcome (reissue reads; reconcile writes by `idem`).
- For a `stale_timestamp` answering a rid that was sent more than once, the device computes its clock
  offset as `host_ms` minus its device time of the **first** send, not of the latest resend.
- A replayed `stale_sequence` carries an old `high`; `max(counter, high + 1)` stays correct.

### 8.9 What the relay checks on the bridge

**P3-D8/D9/D10/D16/D17/D22.** §19.3 and §19.6 add epoch hints, replay coalescing,
non-consuming polls, durable host cursors and holder fencing. Limits cover the whole envelope.
The relay checks membership; operations and scopes stay sealed. New old-epoch response bytes
are accepted only for a known rid with `LAST | REFUSAL`; a live identical replay does not
extend TTL, and an expired identical chunk is stored again only within P3-D27's bounds.
Request and response epochs must match.

The relay holds no keys. It MUST still enforce, before it queues anything:

- **Route and header.** The route's workspace equals the header's. The magic, version and suite are right.
  The mailbox id equals the rid.
- **Device requests (epoch ≥ 1)** come from a device session whose `device_id` equals the header's
  `device`, and which is in the workspace's current member list and not revoked.
- **Pairing requests (epoch 0)** arrive on an unauthenticated pairing route. It is limited per workspace
  and per client address, and the envelope is at most 64 KiB.
- **Responses** are posted only by the workspace's host session.

Sealed bodies live 60 s (v1). **DECIDED HERE:** the relay checks the header's device against the session
and the member list. This is defence in depth: a removed device cannot even queue.

## 9. Push

**D45/D46 (P3 design §7).** Delivery uses APNs and the native Notification Service Extension
(NSE), not Web Push or a service worker. The signed/sealed payload remains as below; delivery
registration is P4.

The relay sees only the outer object, and forwards it as the Web Push payload (spec §6.3):

```
{"v":2, "ws": hex, "epoch": e, "c": b64u(SALTED-AEAD(K_push(e), "orch/v2/push-msg",
                                              "orch/v2/push-aad|" || suite || ws || u32(e), cj(inner)))}
inner   = {"p": payload, "sig": b64u(Sign(WSK, "orch/v2/sig/push|" || suite || ws || u32(e) || cj(payload)))}
payload = {"kind", "id", "label", "ts_ms"}                         exactly these four
```

- `kind` is one of `question`, `question.closed`, `ticket.update`, `drop.new`, `peer.ticket`, `join`.
- `label` is at most 80 code points.
- The whole outer object is at most 3,072 bytes.

**The service worker** keeps, per workspace, the pinned `wsk_pub`, the `WK`s it holds, and the highest
`ts_ms` it showed per `(ws, id)`. It drops the payload if:

1. it is too large, or its outer shape is wrong;
2. it holds no key for `(ws, epoch)`;
3. the tag fails, or `inner` is not exactly `{p, sig}`;
4. **the signature does not verify with the workspace's `WSK`**;
5. the payload shape is wrong, or the kind unknown;
6. `ts_ms` is outside `[now − 24 h, now + 300 s]`;
7. **`ts_ms` is not higher than the last one it showed for `(ws, id)`** (a replay).

Otherwise it shows `label` with `tag = id`, and records `ts_ms`.

**DECIDED HERE:**

- `ts_ms` in the payload: the spec's `{kind, id, label}` would let the relay replay a months-old
  notification forever.
- A `WSK` signature inside the sealed payload: a member device holds `K_push` too, and without the
  signature it could forge a notification in the host's name. That was R3; it is now closed.

Vectors: `push.cases` (including `forged_by_a_member_device`, `replayed`, and
`older_after_newer_for_the_same_id`).

## 10. Drop

### 10.1 Objects

- A space is `personal`, `workspace` (key `WK_e`) or `shared` (key `SK_e`).
- An object is a `file` (version 1 only, immutable, with an expiry) or a `document` (versions 1, 2, …).
- Each version has its own `DEK`, its own content blob and its own signed descriptor.

### 10.2 Content and metadata

The content blob is TIX's SHR1 chunk layout (`crypto.js` `encryptBlob`) under a v2 header and a derived
key:

```
header (40) = "ORD2" || u8(2) || u8(suite) || u16(0) || object_id (16) || u32(version) || u32(chunk_size)
              || nonce_prefix (8)
K_content   = HKDF(DEK, "", "orch/v2/drop-content|" || hex(object_id) || "|" || dec(version))
chunk i     = AES-256-GCM(K_content, nonce_prefix || u32(i), chunk, AAD = header || u32(i) || u8(is_last))
```

- The default chunk size is 1 MiB, at most 64 MiB.
- Empty content is one empty last chunk.
- The `is_last` byte stops truncation; the header binds the object and version.

**Metadata** (name, MIME type, size, transcript) is
`AES-256-GCM(HKDF(DEK, "", "orch/v2/drop-meta|obj|ver"), zero nonce, cj(meta),
"orch/v2/drop-meta-aad|" || suite || object_id || u32(version))`. The zero nonce is safe because the `DEK`
is per version.

Vectors: `drop` (`blob` of 3 chunks, `empty_blob`, `meta_sealed`; truncations refused).

### 10.3 Wraps

A wrap record is `{"object_id", "version", "target_kind", "target_id", "key_version", "wrap"}`.

| `target_kind` | When (spec §6.4) | `wrap` |
|---|---|---|
| `wk` | the writer is a member of that workspace | `SALTED-AEAD(HKDF(WK_e, "", "orch/v2/wrap-wk\|ws\|e"), "orch/v2/wrap-msg", AAD, DEK)` |
| `sk` | shared space | the same with `SK_e` and `orch/v2/wrap-sk\|space\|e` |
| `wxk` | addressed to a workspace, any writer; inbox | `seal_to(WXK_v, "drop-dek", object, v, DEK, extra = 0x01 \|\| u32(version))` |
| `device` | addressed to a device | `seal_to(dk_kx, "drop-dek", object, 0, DEK, extra = 0x02 \|\| u32(version))` |

`AAD = "orch/v2/wrap-aad|" || suite || u8(len(kind)) || kind || target_id || object_id || u32(version) ||
u32(key_version)`. A wrap moved to another object, version or target kind fails (vectors
`wrap_negative`).

### 10.4 Version descriptor

A signed object, kind `drop_object`, signed by its author: `dk_sig` of a device (`author_kind: "device"`) or
the workspace's `WSK` (`"workspace"`). Exactly these fields:

```
object_id, space_id, space_kind, object_kind, version, parent (= version − 1),
parent_hash (null at version 1, else §10.6), author_kind, author_id,
content_hash (b64u H(blob)), content_len, dek_commit (b64u H("orch/v2/dek-commit|" || object_id
|| u32(version) || DEK)), meta (b64u, §10.2), recipients ("inbox" or a sorted unique list of ids),
origin ("human" | "agent"), created_ms, expires_ms (integer | null)
```

**Readers MUST:**

1. verify the descriptor with the author's key, and that the author may write to that space;
2. check `H(blob)`;
3. after unwrapping, check `dek_commit`, then decrypt.

**Why wraps are unsigned.** The signed `content_hash` and `dek_commit` make substituted blobs and wraps
fail. **DECIDED HERE:** `dek_commit`. AES-GCM is not key-committing, so without it a malicious author could
give two recipients two `DEK`s that open one blob to two different plaintexts.

**Agents.** `origin: "agent"` is set by the host for objects an agent sealed through the socket API (spec
§5.5). Vectors: `drop.descriptor_cases`.

### 10.5 Claim-once

`POST /drop/{id}/claim` with:

```
{"o": {"v":2, "suite", "kind":"drop_claim", "object_id", "workspace_id",
       "wrap": <wrap record, target_kind "wk", target_id = workspace_id>},
 "sig": b64u(Sign(WSK, "orch/v2/sig/drop-claim|" || cj(o)))}
```

The relay, in **one transaction**:

1. verifies the signature with the claimer's card → 401 `bad_signature`;
2. checks the shape → 400 `malformed`. The wrap's `version` MUST be the object's version, and its
   `key_version` MUST be the claimer's current epoch from its accepted member list (§7.2): a claim cannot
   leave behind a wrap that no current member can open;
3. if the object is already claimed:
   - by the same workspace → 200 (idempotent);
   - otherwise → 409 `already_claimed`, with `claimed_by`;
4. checks that the claimer holds a `wxk` wrap on the object → 403 `not_eligible`;
5. stores the new wrap, sets `claimed_by`, and **deletes every other wrap**.

**DECIDED HERE:** claims are idempotent, and the loser learns the winner's workspace id (a routing id).
Vectors: `drop.claims` (a race won by B, idempotency, a wrong signer, a wrap for another workspace, another
version, another epoch), and the round trip `test_round_trip_drop_claim`.

### 10.6 Documents

- **Parent hash.** Every version descriptor carries `parent_hash`. It is `null` at version 1, and
  otherwise `b64u(H("orch/v2/drop-parent|" || cj(parent descriptor o)))`.
- `PUT /drop/{id}/versions` carries the new descriptor, its wraps and its blob, with `If-Match: <current
  version>`.
- `If-Match` is a decimal without leading zeros; missing or malformed is 428 `precondition_required`.
- **The relay accepts only if all hold:**
  - `If-Match == current`;
  - `parent == current` and `version == current + 1`;
  - `parent_hash` is the hash of the current head descriptor.

  Otherwise it answers 409 `version_conflict` with `current` ("fetch first").
- There is no merge.
- `POST /drop/{id}/lease` (10 min by default) is advisory and is not checked on `PUT` (spec §6.4).
- **Readers check the chain.** A reader MUST check that each version's `parent_hash` is the hash of the
  version before it, from version 1 up (`fork` otherwise). It MUST also persist the highest version it
  has seen per document, and treat a lower "latest" as an error.

**DECIDED HERE:** `parent_hash`. Without it, a relay could serve two writers two different histories with
the same version numbers (a fork), and neither would notice. With it, the history every reader sees is one
hash chain, signed version by version by its authors; a fork shows up at the first diverging version. That
was R6 for documents; it is now closed.

Vectors: `drop.documents` (including `fork_parent_hash_of_another_version_3` and `first_version`),
`drop.document_chains` (`valid`, `fork_served_by_the_relay`, `version_missing`).

## 11. ws→ws envelopes (spec §9)

### 11.1 Layout

```
envelope = header (60) || u32(body_len) || body || signature (64) [ || u32(cosig_len) || cj(cosig) ]
header   = "ORWX" || u8(2) || u8(suite) || u8(flags) || u8(0) || id (16) || from_ws (16) || to_ws (16)
           || u32(wxk_version)
```

- `flags` bit 0x01 is `COSIGNED`, and the co-signature block is present exactly when it is set.
- `flags` bit 0x02 is `REFUSAL`: the envelope is a refusal (§11.5) and is never answered.
- Unknown flag bits and a non-zero reserved byte are dropped.
- The envelope is at most 1 MiB; larger attachments go through Drop.

**DECIDED HERE:** the binary form of the spec's `{v, id, from_ws, to_ws, wxk_version}`, with magic, suite
and flags added.

### 11.2 Body

```
body = seal_to(WXK_{wxk_version} of to_ws, "ws-envelope", object = id, epoch = wxk_version, cj(b),
               extra = header)
b    = {"kind", "in_reply_to", "depth", "deadline_ms", "ticket", "result", "refusal", "attachments"}
```

- **`kind`** is one of:
  - `ticket` (`ticket` set, `in_reply_to` null);
  - `result` (summary, Drop references and status in `result`);
  - `refusal` (§11.5);
  - `question.closed` (spec §8).
- **The header is in the seal's AAD.** **DECIDED HERE.** Signature alone would let a pinned peer lift
  another peer's sealed body, re-sign it under its own header, and have the receiver read A's content as
  B's (vector `body_lifted_under_another_senders_header`).
- **DECIDED HERE:** the spec's body fields plus `result` and `refusal`, with an exact field set.

### 11.3 Signature and human co-signature

```
signature    = Sign(WSK_from, "orch/v2/ws-envelope|" || header || body)
envelope_hash = H("orch/v2/ws-envelope-hash|" || header || body)
```

The signature covers the `COSIGNED` flag, so a stripped co-signature is detected. A co-signature is one of
two forms.

**Device key:**

```
{"type":"device", "cert": <signed device_cert>, "sig": b64u(Sign(dk_sig, "orch/v2/sig/ws-cosign|" || envelope_hash))}
```

**WebAuthn:**

```
{"type":"webauthn", "cert", "credential_id", "credential_pub" (65-byte P-256),
 "bind_sig": b64u(Sign(dk_sig, "orch/v2/sig/webauthn-bind|" || lp16(credential_id) || credential_pub)),
 "rp_id", "origin", "authenticator_data", "client_data_json", "signature" (DER)}
```

The receiver checks the chain **DK → certificate → the peer's pinned owner PK** (spec §9):

- the certificate is valid, not revoked, and not a scoped agent;
- for WebAuthn, also:
  - `bind_sig`;
  - `type = "webauthn.get"` and `challenge = b64u(envelope_hash)`;
  - `origin` equals the sender card's `relay_url`, and `rp_id` is its host;
  - the rpIdHash;
  - the UP and UV flags;
  - the ES256 signature.

The receiver keeps no sign count.

**DECIDED HERE:** the binding signature. A receiver has never seen the sender's passkey, so the passkey's
key must be vouched for by the device key.

Vectors: `cosigned_by_device_key`, `cosigned_by_webauthn`, `cosigned_by_a_revoked_device`,
`cosignature_of_another_persons_device`, `cosigned_flag_but_cosignature_stripped`.

### 11.4 What the receiver does (normative order)

1. **Shape.** Size, magic, version, the reserved byte and unknown flags → drop. The suite → drop.
   `to_ws` is itself → drop.
2. **Pin.** `from_ws` is in the address book → otherwise drop (an unpinned sender is never answered).
3. **Signature** with the pinned `wsk_pub` → drop.
4. **Duplicate.** Seen ids are keyed by **`(from_ws, id)`**. A pair seen before with the same
   `H(header || body)` returns the stored outcome and does nothing new. Other bytes under a seen pair →
   drop. The same `id` from another sender is a different envelope (vector `same_id_from_two_senders`).
5. **Co-signature**, if flagged → `bad_cosignature`. Trailing bytes without the flag → drop.
6. **WXK version.** Current, or previous with `now < retired_ms + 14 d` → otherwise `stale_wxk` with the
   current `wxk_version`.
7. **Open and parse** strictly → `malformed`. This needs:
   - the exact field set and a known kind;
   - the `REFUSAL` flag set exactly when `kind` is `refusal`;
   - for a refusal, a known code.
8. **For `ticket`:**
   - `in_reply_to` not `null` → `malformed`;
   - `depth > 1` → `depth_exceeded`;
   - `deadline_ms > now + 30 d` → `malformed`;
   - `deadline_ms + 300 s < now` → `deadline_passed`;
   - otherwise the inbox, marked `from-peer` (spec D13).
9. **For the replies** (`result`, `refusal`, `question.closed`): `in_reply_to` MUST name an envelope this
   workspace sent to `from_ws`, whose reply of that kind has **not been taken yet** → otherwise
   `unknown_reply`.
   - `result` and `refusal` are final, and each takes both: after a result, a refusal or a second result
     for the same envelope is refused, and the other way round. A late replay of an answer can therefore
     never be delivered.
   - `question.closed` is taken once on its own.
   - A result past its deadline is delivered, marked `late`.

**When the envelope carries `REFUSAL`, every "refuse" above becomes a drop** (§11.5).

From step 5 on, the outcome is stored with `(from_ws, id)` until `max(now, deadline) + 7 d`. The sender
keeps `sent[id] = {to, consumed kinds}` until the ticket's deadline plus 7 d. **DECIDED HERE:** the
`(from_ws, id)` key and the consumption of replies.

Vectors: `ws_envelopes.cases` (34 per suite), and the round trip
`test_round_trip_ws_ticket_refusal_and_result`.

### 11.5 Refusals

A refusal is itself an envelope to the sender, sealed to the sender's `WXK`, with **flag `0x02 REFUSAL`**
set in its signed header:

```
b = {"kind":"refusal", "in_reply_to": <refused id>, "depth": 0, "deadline_ms": now, "ticket": null,
     "result": null, "refusal": {"code", "wxk_version"?}, "attachments": []}
```

The codes are `stale_wxk` (with `wxk_version`), `depth_exceeded`, `deadline_passed`, `bad_cosignature`,
`unknown_reply` and `malformed`.

- **An envelope with `REFUSAL` is never answered.** Whatever is wrong with it, the receiver drops it. The
  flag is in the signed header, so neither the relay nor a peer can remove it to start a refusal loop.
- A body of kind `refusal` without the flag, or the flag on another kind, is `malformed` (dropped when the
  flag is set).
- Drops (steps 1–4 of §11.4) are never answered.

**DECIDED HERE:** refusals are sealed envelopes, so the relay does not learn the refusal code; and the
`REFUSAL` flag. Vectors: `refusal_for_a_ticket_we_sent`, `refusal_after_a_result_refused_silently`,
`refusal_for_a_ticket_we_never_sent_is_dropped_not_answered`, `refusal_flag_on_a_result_body_is_dropped`,
`refusal_body_without_the_flag_is_malformed`.

## 12. Publish request signing and relay authentication

### 12.1 orch-publish (spec §10)

**Headers:**

- `Orch-Workspace: <hex>`;
- `Orch-Ts: <decimal ms, no leading zeros>`;
- `Orch-Nonce: <32 lower-case hex>`;
- `Orch-Signature: <b64u>`.

```
signed = "orch/v2/publish|" || suite || workspace_id || u64(ts_ms) || nonce (16) || lp16(METHOD)
         || lp16(host) || lp16(request-target) || H(body)
```

- `host` is the lower-case host the client sent, with a port only if it is not the default.
- `request-target` is the path and query exactly as sent: not normalised, not decoded.

**orch-publish checks, in order:**

1. header syntax → 400 `malformed`;
2. `|now − ts| ≤ 120 s` → 401 `stale_timestamp` with `server_ms`;
3. the card is known (verified against the directory, and cached until it changes or a revocation
   arrives) → 401 `unknown_workspace`;
4. the signature → 401 `bad_signature`;
5. the nonce is unseen for this workspace → 401 `replay`. Then it records the nonce for 240 s.

The signature comes before the nonce store, so junk cannot fill it. 240 s is twice the window, so a replay
after the nonce expired is stale anyway (vector `replay_after_nonce_retention_is_stale`).

**DECIDED HERE:** the byte layout, the header names, and the nonce length and retention. Vectors:
`publish.cases`.

### 12.2 Relay sessions

**P3-D2/D17.** See §19.4 for concurrent 15-minute tokens, dummy-key verification for unknown
ids, refusal of revoked devices after signature verification, expiry/revocation checks on every
request and at long-poll handoff, and challenge budgets. There is no refresh token.

The client gets `{challenge (32 bytes), expires_ms (60 s)}` from the relay and answers with:

```
signed = "orch/v2/sig/relay-auth|" || suite || lp16(origin) || challenge || u8(1 device | 2 workspace) || id (16)
```

It signs this with `dk_sig` (the relay checks the certificate and revocations) or with `WSK` (the relay
checks the card). The session is an opaque bearer token, valid for 15 minutes. Agents never see it (spec
§5.5).

**The relay checks, in order:**

1. the challenge is one it issued. It is **removed whatever happens next** → 401 `unknown_challenge`;
2. `now < expires_ms` → 401 `expired`;
3. `kind` is `device` or `workspace` → 400 `malformed`;
4. the signature over the bytes above, built with **the relay's own origin**, never one the client names →
   401 `bad_signature`.

**DECIDED HERE:** the layout, a single-use challenge of 60 s, the check order, and 15-minute sessions.
Vectors: `relay_auth`, `relay_auth.cases` (valid then reused, expired, another origin, signed as another
kind, another key, an unknown kind).

## 13. Questions (spec §8)

**P3 design §7 / D40.** The host records a verified decision verbatim as F1 `evidence`. Every
`decision_id` and admitted person-event id is single-use forever, across restores. The existing
F1 `cj({contract, suite, workspace_id, log, event})` context remains the signature input.

- `question_id` of a ticket question is the F1-derived id: the first 16 bytes, in hex, of
  `H("orch/v2/question-id|" || cj({"workspace_id", "ticket", "question"}))` (ticket format F1 §5.6, row
  `h_question_id`). It is not random; a question of another origin may use 16 random bytes (hex).
- `content_hash = b64u(H("orch/v2/question|" || cj({question_id, ticket, text, options})))`.
- A decision is the bridge op
  `{"op":"decision", "decision_id": hex, "question_id": hex, "content_hash": b64u, "answer": <JSON>,
  "sig": b64u}`, with exactly these fields.
- `sig` is a **detached** signature by the device's `dk_sig`:

  ```
  sig = Sign(dk_sig, "orch/v2/sig/decision|" || cj({"workspace_id", "question_id", "content_hash",
                                                   "decision_id", "answer"}))
  ```

  The bridge envelope already authenticates the request. The detached signature lets the decision travel
  on as a device-signed ledger entry (spec §12: "decisions from devices carry device-key signatures") and
  to a peer the question came from. `workspace_id` binds it to one workspace. The host checks the field
  set → `malformed`, then the signature with the sender's certificate → `bad_signature`, before
  compare-and-set.
- A decision is single-use by `decision_id`. Because the qid is derived, the same question id and text can
  recur (for example after a `restore`); whether a decision bound to an abandoned chain is refused is **open
  for P3** (F1 §5.10 `abandoned_decisions`), not defined here.

The host applies the first valid decision by compare-and-set, then:

- pushes `question.closed` with label `"Answered on <device label>"` to every member device;
- sends a `question.closed` ws envelope to the peer, if the question came from a peer.

Refusals:

- a later decision → `already_answered`, with `by_device_label` and `at_ms`;
- a `content_hash` that is no longer current → `question_changed`, with the current `content_hash`.

Clients reconcile on open by fetching each question's state. **DECIDED HERE:** the hash input, the op, its
detached signature (the review's `ws` field is spelled `workspace_id`, like everywhere else), and
`question_changed`. Vectors: `question_hash`, `decisions` (valid, answer changed, replayed into another
workspace, signed by another device, without signature).

## 14. Refusal codes

A refusal carries its code plus only the fields listed here, and never echoes request content. A device
shows its own fixed text per code.

**Bridge (sealed, host-signed; v1 codes unchanged unless noted):**

| Code | Fields | Note |
|---|---|---|
| `malformed` | — | |
| `not_visible` | — | restricted ticket, P3-D14 |
| `not_member` | — | was v1 `not_paired` |
| `revoked` | — | |
| `bad_signature` | — | |
| `rid_conflict` | — | |
| `already_done` | `status` | |
| `stale_timestamp` | `host_ms` | |
| `stale_sequence` | `high` | |
| `stale_epoch` | `epoch` | new (§8.5) |
| `pairing_closed` | — | |
| `other_person` | — | new: a certificate or revocation of another person (spec D1 C) |
| `cert_invalid`, `cert_expired` | — | new |
| `forbidden_scope` | — | |
| `assertion_required`, `lease_required` | v1 §9.4's challenge fields | |
| `assertion_failed` | — | |
| `scope_changed`, `stopped` | — | |
| `busy` | — | |
| `already_answered` | `by_device_label`, `at_ms` | new (§13) |
| `question_changed` | `content_hash` | new (§13) |

Every answer to an epoch-0 request, refusals included, also carries `wsk_pub`.

**ws→ws (sealed envelopes with the `REFUSAL` flag, §11.5):** `stale_wxk` (`wxk_version`),
`depth_exceeded`, `deadline_passed`, `bad_cosignature`, `unknown_reply`, `malformed`.

**Relay and orch-publish HTTP** (`{"error": code, …}`):

| Status | Codes |
|---|---|
| 400 | `malformed`, `wrong_suite`, `cert_invalid`, `cert_expired`, `delegation_mismatch`, `too_large` (P3-D1/D17) |
| 401 | `bad_signature`, `stale_timestamp` (`server_ms`), `unknown_workspace`, `replay`, `unknown_challenge`, `expired`, `unauthenticated` (P3-D2) |
| 403 | `revoked`, `other_person`, `scope_exceeded`, `not_eligible`, `not_for_this_device`, `cert_expired` (membership publication, P3-D7) |
| 404 | `not_found` (P3-D1) |
| 409 | `other_workspace`, `wsk_changed`, `delegation_changed`, `stale_card`, `wxk_changed_without_version`, `bad_wxk_version`, `stale_list`, `bad_epoch`, `rotation_required`, `wk_commit_changed` (G2b), `missing_grant`, `already_claimed` (`claimed_by`), `version_conflict` (`current`), `account_exists`, `cert_conflict`, `grant_conflict`, `wrap_conflict` (G0a review 10), `rid_conflict`, `retry_exhausted`, `chunk_conflict`, `stale_epoch` (`epoch`, unsigned hint), `holder_conflict`, `fenced`, `request_open`, `replayed`, `already_signed` (P3-D3/D5/D7–D11/D22/D27), `no_genesis`, `genesis_mismatch` (P3-D18), `chain_diverged`, `restore_invalid`, `restore_not_owner`, `restore_source_mismatch`, `restore_reused`, `restore_missing_revocation` (`devices`: sorted device IDs; P3-D13/D24), `staging_conflict`, `staging_incomplete` (P3-D20), `checkpoint_time` (P3-D25) |
| 413 | `too_large` for JSON routes (G0a review 2); before parsing |
| 410 | `checkpoint_gone` (P3-D19/D20; a previously stored endpoint expired), `expired` (P3-D11; unknown/expired response rid, G0a review 8) |
| 429 | `rate_limited`, `quota_exceeded` (P3-D5/D17; `Retry-After`) |
| 503 | `overloaded` (P3-D17; `Retry-After`) |
| 428 | `precondition_required` |

**Primary device (local, never on the wire):**

- for cert requests (§8.4): `other_person`, `bad_signature`, `not_for_this_device`, `expired`, `replayed`,
  `request_open`, `malformed`, `scope_exceeded`, `already_signed`, `rejected`, and the warning
  `client_hosted`;
- for enrolment (§6.4): `bad_signature`, `malformed`, `unknown_code`, `used`, `expired`, `bad_mac`.

**Phone, on a pairing answer (drops, never sent):** `not_my_key` (raises the alarm),
`challenge_signature`, `not_for_this_workspace`, `challenge_expired`, `pk_pin`, `wsk_pin`.

**Service worker (drops):** `signature`, `replay`, `stale`, `no_key`, `tag`, `payload`.

**Document reader:** `fork`.

## 15. Clock rules

Every check uses the verifier's own clock. The one exception is the device's clock offset, which a device
adopts only from a verified `stale_timestamp` refusal, once per pending rid, within ±24 h (v1 §5.1).
Boundaries are inclusive where the cell says ≤.

| What | Rule |
|---|---|
| Bridge request | `\|host_now − ts_ms\| ≤ 300 s`; rid record kept `received_at + 900 s`, never derived from `ts_ms` |
| Bridge response | `\|device_now + offset − ts_ms\| ≤ 300 s` |
| Pairing offer | 10 min, single use; the host keeps the offer record 24 h to answer `pairing_closed` |
| `cert_pending` | 10 min from entering the state, then `expired` |
| Cert request | `created − 300 s ≤ now < expires`, and `expires − created ≤ 10 min` |
| Cert challenge | the phone accepts it while `now (+ offset) < expires_ms` (the request's expiry) |
| Device certificate | `created_ms ≤ now + 300 s`; expired when `now ≥ expires_ms` |
| Push payload | `now − 24 h ≤ ts_ms ≤ now + 300 s`, and higher than the last shown for `(ws, id)` |
| ws ticket | `deadline_ms + 300 s ≥ now`, and `deadline_ms ≤ now + 30 d`; seen ids kept to `max(now, deadline) + 7 d` |
| WXK overlap | previous key accepted while `now < retired_ms + 14 d` |
| Publish | `\|now − ts\| ≤ 120 s`; nonces kept 240 s |
| Relay login | challenge 60 s, single use (expired when `now ≥ expires_ms`); session 15 min |
| Enrolment code | expired when `now ≥ expires_ms`; one use |
| WebAuthn challenges | 120 s (v1) |
| Epoch age | rotate at 90 days (host clock), checked at startup and daily |
| Stream silence | 60 s (v1); keepalive at least every 20 s |

## 16. Test vectors

`tests/vectors_v2.json` holds the same sections for **each suite** (`suites."1"`, `suites."2"`). All keys
are FAKE (`SHA-256("FAKE orch v2 test vector: " || label)`), and so is every "random" value.

- **Single-call cases** give the exact inputs, the state, the clock and the expected result.
- **Chains** (`steps`) run against one state, so what a step leaves behind is checked too.
- The `why` of a drop is informative and not part of the contract.

| Section | Covers |
|---|---|
| `labels`, `constants`, `encodings` | every label (§3); limits; canonical JSON, strict parsing, canonical b64u |
| `ed25519_small_order` | the 8 small-order encodings, computed |
| `sign` | valid, other key, changed message, short; suite 1: S ≥ L, small-order, identity and non-canonical keys; suite 2: the malleable twin, r = 0, s = n, off-curve key |
| `hkdf`, `salted_aead` | every derived key with its `info` text; one SALTED-AEAD |
| `seal`, `seal_open` | sealing to a device with every intermediate; opening with the wrong purpose, recipient, object, epoch or key, and tampered |
| `label_sealed` | §5.4 |
| `certs` | 16 cases (§6.1) |
| `revocations`, `revocation_op` | valid, another person, wrong key, bad reason; the bridge op (§6.2) |
| `card` | delegation, sealed part, `ck_commit`, card-key wrap, 16 update cases |
| `wk_grants`, `member_lists` | grants; 34 member-list cases (§7.2), including the G2b first-list, skip, fall, u32, removal and `wk_commit` rules |
| `wk_commit` | the commitment for given `workspace_id`, epoch and `WK` (§7.2, G2b) |
| `member_list_snapshots` | device steps (§7.3 D1–D4): high-s twin no-op, conflicting content (also with another `wk_commit`, no sealing block), `wk_commit_conflict` (also from a lower `list_seq`), grant/commit mismatch, no fallback, reading after a jump and `future_epoch`, first contact, lower `list_seq`, fall, removal |
| `bridge.seal`, `bridge.host_cases`, `bridge.device_cases`, `bridge.pair_answers`, `bridge.links`, `bridge.sas` | §8, including the R1 attack |
| `cert_request` | 10 primary cases, the challenge and its code, the certificate, a second signature refused, the attack challenge (§8.4) |
| `enroll`, `webauthn`, `question_hash`, `decisions` | §6.4, §8.7, §13 |
| `push` | §9: valid, unknown workspace or epoch, 24 h edge, changed epoch, unknown kind, extra field, forged by a member device, replays |
| `drop` | content blob (3 chunks, empty), metadata, every wrap kind and moved wraps, descriptors, claims (with version and epoch checks), documents, chains and forks |
| `ws_envelopes` | layout, both co-signatures and five WebAuthn negatives, refusal envelopes, reply consumption, ids per sender |
| `publish`, `relay_auth` | §12, including challenge reuse, expiry, another origin, another kind, another key |

**Round trips.** `tests/test_vectors.py` also feeds one side's output into the other side's checks:

- pairing through `cert_pending` (phone → host → primary → host → phone);
- the R1 attack;
- a bridge request and a `stale_epoch` refusal;
- a card;
- a ws ticket, its refusal and a late result;
- a Drop claim.

Every implementation (orch-core host, orch-relay, orch mobile) MUST run the vectors of its deployment's
suite in its own test suite.

**Not covered by vectors yet** (see §18):

- quota and store-limit cases beyond `quota_busy`. They are v1's rules, unchanged, and v1's `quota_*`
  vectors describe them;
- SK grants;
- the `drop_rewrap`, `member_remove` and `new_ticket` ops on the host;
- WebAuthn registration parsing (v1 F2).

## 17. Decisions taken here

**P3 amendment.** P3-D1–D11, P3-D14–D17, P3-D22 and P3-D27 below and in §19 supersede the earlier
HTTP, membership and bridge transport rules. D45/D46 select native clients and suite 2.
Checkpoint/restore decisions P3-D12/D13/D18–D21/D23–D25 are specified in §19.8 (G0b).

Each is marked **DECIDED HERE** where it is used; the reviewer may reverse any of them. Items marked
*(review)* were added or changed after the first review of PR #23.

1. Suite ids `1` and `2`, a suite byte in every binary layout and a `suite` field in every JSON object; a
   suite mismatch is dropped (§1.1).
2. A device has two key pairs, `dk_sig` and `dk_kx` (§1.1).
3. Ed25519 strictness: canonical S, canonical keys, no small-order keys (§1.2).
4. Ids in hex, every other byte string in canonical b64u (§2.2).
5. The JSON subset: no floats, ASCII keys, safe integers, signatures over `cj(o)` after strict parsing
   (§2.3, §2.4).
6. Trailing `"|"` on the spec's `orch/v2/ws-envelope` and `orch/v2/publish` domains (§3).
7. The 6-character pairing code binds a host nonce revealed only to the device that consumed the offer
   (§4).
8. `WSK` never rotates; the relay refuses a changed `wsk_pub` (§5.2).
9. A fresh `DEK` for every document version (§5.2).
10. The seal purposes, and their `object_id`, `epoch` and `extra` (§5.3).
11. `label_sealed` under a key derived from the personal vault key (§5.4).
12. Scopes as a prefix list of v1's ordered levels; `expires_ms` always present (§6.1).
13. Revocation reasons, and no un-revoke (§6.2).
14. *(review)* The bridge op `revocation`, authorised by `PK`'s signature whoever relays it (§6.2).
15. The scoped-agent enrolment link and MAC, and the primary's check order (§6.4).
16. The recovery kit's format is deferred to P1 (§6.5).
17. *(review)* The card: a one-time `PK`-signed delegation (with `client_hosted` in the clear), and the
    rotating card signed by `WSK` alone. The client-hosted marker is decided by the delegation flag, and
    the sealed name only names. Also `sealed_hash`, `ck_commit`, `card_seq`, the relay URL form and the
    update rules (§7.1).
18. `list_seq` beside `epoch`; one `WK` per epoch, ever, committed by `wk_commit`; a refused publication burns
    its epoch and `list_seq`, so epochs may skip (at most `2^16` per list) and never fall, and the first list
    takes any epoch `1 … 2^16` (G2b, P3-D26); the relay requires grants before the list, and checks the first
    list's workspace against the card (§7.2).
19. WK grants are signed by `WSK`; a device's current epoch never moves backwards (§7.3).
20. The bridge header: magic `"ORB2"`, `suite` in place of `key_version`, a `u32` epoch, and the offer id in
    `stream` at epoch 0 (§8.1).
21. A fifth link field `pk_pin`; no pairing MAC (§8.3).
22. *(review)* The `pair_status` answer shapes. All carry `wsk_pub`; `pending` repeats the full five fields;
    `cert_pending` carries `pk_pub` and the challenge; there is an `expired` state. The window applies to
    every answer except a verified `stale_timestamp` (§8.3).
23. *(review)* `cert_pending` with a `PK`-signed challenge: the primary draws its nonce, and the phone checks
    the keys and shows `cert_code`. The primary signs once, only for its own challenge's keys and only while
    it is unexpired and not rejected. It keeps at most one open request per workspace, where "open" means
    unexpired and neither signed nor rejected, and refuses drop scopes and replays. Client-hosted is a
    warning. Also the UI rules for the two codes (§8.4).
24. `stale_epoch` handling; nothing new is ever sealed under an old epoch; a `stale_epoch` not higher than
    the request's is dropped (§8.5).
25. The `epoch` in the WebAuthn assertion challenge (§8.7).
26. The relay checks the header's device against the session and the member list (§8.9).
27. *(review)* Push: `ts_ms` with a 24 h maximum age, a `WSK` signature inside the sealed payload, and a
    replay rule per `(ws, id)`; a 3,072-byte cap (§9).
28. The Drop content header `"ORD2"`; per-version metadata keys (§10.2).
29. `dek_commit` in the descriptor (§10.4).
30. *(review)* Idempotent claims; the loser learns `claimed_by`; the relay checks the wrap's version and its
    epoch against the claimer's member list (§10.5).
31. *(review)* `parent_hash` chains document versions; the relay and readers check it (§10.6).
32. The ws envelope's binary header with magic, suite and flags (§11.1).
33. The header in the body's AAD; the extra body fields `result` and `refusal` (§11.2).
34. The WebAuthn co-signature's `bind_sig`, and its origin tied to the sender card's relay (§11.3).
35. *(review)* Seen ids keyed by `(from_ws, id)`; replies consume the sender's `sent` entry per kind
    (§11.4).
36. *(review)* Sealed refusal envelopes with a signed `REFUSAL` flag; such an envelope is never answered
    (§11.5).
37. The publish signature layout, its headers and its nonce rules (§12.1).
38. Relay login layout and lifetimes, and its check order (§12.2).
39. *(review)* The question hash input, the `decision` op with a detached `dk_sig` signature over
    `workspace_id` and the decision, and `question_changed` (§13).

Taken out after review: the first draft's item "the primary refuses cert requests from client-hosted
workspaces" (now a warning), and "ids derived from keys" (the owner accepted it, and spec §4 is being
amended).

## 18. Open risks and follow-ups

**Closed in review:**

- **R1, a forged certificate through a malicious host.** Fixed by the primary's `PK`-signed challenge
  (§8.4). The phone shows a code only for a challenge naming its own keys. Vectors and a round trip show
  the attack failing.
- **R3, push forgery by a member device.** Fixed by the `WSK` signature inside the payload (§9).
- **R6, rollback and forks.**
  - Documents: closed by `parent_hash` (§10.6).
  - Cards: `card_seq` rises strictly at the relay, and peers MUST persist the highest `card_seq` they have
    seen and refuse a lower one.
  - Epochs: never move backwards on a device (§7.3).

**D45/D46 (P3 design §7):** R2 is closed by native distribution, R5 by suite-2 deployment.
The historical web risks below apply only to a future browser client.

**Open:**

- **R2, web-delivered JavaScript** (spec §4) is unchanged. A compromised `/app` at pairing time owns the
  device key. Nothing in this protocol narrows that beyond spec §4.
- **R4, one device id across workspaces** (§4) lets the relay link a device's traffic across workspaces.
  The owner accepted this; spec §4 is being amended.
- **R5, suite 1 depends on spike S1.** If WebCrypto Ed25519/X25519 is unreliable on the oldest supported
  iOS, deployments use suite 2. Every vector exists for both suites.
- **R7, the relay learns `client_hosted`** from the delegation (§7.1). The owner names no one; the text
  stays sealed.
- **R8, the human compares two codes in `cert_pending`.** The phone shows the pairing code first, then the
  challenge's code. Mitigated by the UI rules in §8.4: clear the first code, label the second "compare
  with <primary>", and hide it after `expires_ms`. This remains a usability risk to test on a real phone
  (iPhone session 1).

**Follow-ups:**

- **F1:** vectors for the v1 quota cases in the v2 layout, SK grants, the host ops `drop_rewrap`,
  `member_remove` and `new_ticket`, and WebAuthn registration (CBOR).
- **F2:** a mutation test like v1's (`test_bridge_protocol_mutations.py`), so that every MUST is shown
  to be pinned by a vector.
- **F3:** the `http` meta mapping (method, path, header allow-list) and `new_ticket` belong to the host
  API, as in v1 F3.


## 19. Relay HTTP API (P3-D1)

**P3-D1 (routes and fixtures; C3).**

- All routes start with `/v2`.
- Bodies reuse the FakeRelay's shapes (host-api v0 §1 and §3), without `host_api` and without the `Orch-Host-API`
  header.
- Errors use §14's form, `{"error": code, …}`. JSON is strict per §2.3. `Retry-After` is integer
  delta-seconds.
- This is more than a prefix change for the phone. G0 therefore publishes request/response fixtures
  (`tests/http_fixtures/*.json`, one per row below, including refusals) that the relay tests, the phone's
  adapter and its FakeRelay all consume.

Common semantics:

- **Position cursors** (`after`, `after_n`, `after_seq`) are decimal integers, exclusive, and strictly increasing per
  stream. **Checkpoint references** (`to`, `hash`) are `h_checkpoint` values. `next` is an opaque string that the
  client passes back unchanged; the §19.8 checkpoint read routes are the one exception, where `next` is resubmitted
  as `after_n` (transitions) or `from` (proof), as §19.8 transport detail 3 defines.
- **Pagination** returns at most `limit` items (the default and maximum are listed per route) and **at most 4 MiB per
  response on every route**, plus `next` (null at the end).
- **Long polls** take `wait` from 0 to 25 s.

The **Auth** column uses these codes:

| Code | Meaning |
|---|---|
| none | no session |
| D | device session |
| W(g) | workspace session that holds the current holder generation `g` (header `Orch-Holder: g`, P3-D10) |
| W | workspace session, any generation (read routes) |
| D(m) | device session of a current, unrevoked member of `{ws}` with an unexpired certificate, checked in the same transaction as the read or write |
| D(p) | device session of the same person |

### 19.1 Directory and sessions

(G0a review 1) Each workspace has durable `ever_persons` and `ever_devices` sets, updated only
on accepted member-list publication. A device enters `ever_devices` exactly when it is a member
of an accepted list. A person enters `ever_persons` exactly when an accepted list contains at
least one member device whose stored certificate belongs to that person (check 8 binds this).
Every `persons` entry MUST have at least one member device of that person in the same list;
otherwise publication is refused with 403 `other_person`. Failed publications add no authority.
W certificate and person-feed reads require `ever_persons`; device reads and feed entries are
restricted to `ever_devices`. Apply these filters before pagination and to relevant notices.
Departure never removes historical authority; one workspace's sets never authorize another.

(G0a review 2) Every JSON route below has a whole-body cap in its limits cell, checked before
JSON parsing, authentication or signature verification; excess is 413 `too_large`. KiB = 1024
bytes. Membership retains 2 MiB. GET accepts no body. ORB2 keeps its existing binary caps/status.
Card-key batches may be split across multiple requests within the cap.
Caps apply to streamed bytes as well as declared Content-Length; never buffer above the cap.


| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `POST /v2/session/challenge` | none | `{}` → `{challenge, expires_ms}` | 60 s, single use; per address (/64 IPv6) ≤ 16 outstanding and 60/min; /56 ≤ 256 outstanding and 960/min (G0a review 9); global ≤ 65 536 outstanding, excess **refused** (P3-D17); JSON cap 16 KiB (G0a review 2) | 429 `rate_limited` | §12.2 |
| `POST /v2/session/login` | none | `{challenge, kind, id, sig}` → `{token, expires_ms}` | challenge consumed on every attempt; 15 min; ≤ 8 live tokens/device (G0a review 10); JSON cap 16 KiB (G0a review 2) | 400 `malformed`, `cert_expired`, `cert_invalid`; 401 `unknown_challenge`, `expired`, `bad_signature`; 403 `revoked`; 429 `quota_exceeded` (G0a review 10) | §12.2, §4 |
| `POST /v2/session/logout` | D or W | `{}` → `{}` | idempotent; safe to retry with an expired token (200); JSON cap 16 KiB (G0a review 2) | — | new |
| `POST /v2/accounts` | none | `{invite, pk_pub, device_cert, challenge, sig}` → `{person_id}` | `sig` is the new device's login signature over a fresh challenge; the exact same request → 200 (by digest); JSON cap 64 KiB (G0a review 2) | 400 `malformed`, `cert_invalid`; 401 `bad_signature`, `unknown_challenge`; 403 `not_eligible` (one code for unknown, used or expired); 409 `account_exists` | spec §6.1 (P3-D3) |
| `PUT /v2/devices/{device}` | none | `{cert}` → `{device_id}` | self-authenticating under the account `PK`; per address 30/h; per person 64/day, charged only on verified state changes; canonical retries and refused submissions are free (G0a review 3) (G0a review 5); JSON cap 16 KiB (G0a review 2) | 400 `cert_invalid`, `cert_expired`; 403 `revoked`, `other_person` (no account); 409 `cert_conflict` | §6.1, §8.3, §8.4 (P3-D5) |
| `GET /v2/devices/{device}` | D(p), or W whose `ever_persons` contains the person and `ever_devices` contains the device (G0a review 1) | → `{cert}` | | 403 `not_eligible`; 404 `not_found` | §6.1 |
| `POST /v2/revocations` | none | `{record}` → `{device_id}` | authority is `PK`; per address 10/min; per person 32/day, charged only on verified state changes (G0a review 5), with 8/day reserved for revocations of devices not yet revoked; an exact retry is free; JSON cap 16 KiB (G0a review 2) | 400 `malformed`; 401 `bad_signature`; 403 `other_person` | §6.2 (P3-D5) |
| `GET /v2/devices/{device}/revocation` | none | → `{record}` | per address 60/min | 404; 429 | §6.2, gaps 24 |
| `GET /v2/persons/{person}/revocations?after=&limit=` | D(p), or W whose `ever_persons` contains the person | → `{revocations, next}` | W sees only `ever_devices`, filtered before pagination (G0a review 1); limit ≤ 256 | 403 | §6.2 |
| `PUT /v2/workspaces/{ws}/card` | none for the first card; W(g) after | `{card}` → `{card_seq}` | first card: per address 10/h, per owner account 10/h charged only after delegation and card signatures verify; same-card retries are free (G0a review 5); first writer wins in one transaction; same card → 200; JSON cap 64 KiB (G0a review 2) | §7.1 codes: 400 `malformed`, `wrong_suite`, `delegation_mismatch`; 401 `bad_signature`; 403 `other_person`; 409 `other_workspace`, `wsk_changed`, `delegation_changed`, `stale_card`, `wxk_changed_without_version`, `bad_wxk_version` | §7.1 (P3-D4) |
| `GET /v2/workspaces/{ws}/card` | D(m) or W | → `{card}` | | 403; 404 | §7.1 |

**P3-D3 (accounts; C5).** Accounts come only from single-use invite codes made by the admin CLI
(`orch-relay invite create --ttl 7d`, stored hashed). The request carries the first device certificate (`PK`-signed)
and a fresh login signature by that device over a relay challenge. That proves the applicant holds the device key now.
Invite use and the request digest commit in one transaction. A replay of a captured certificate without the device key
fails. Registering someone's `pk_pub` would need their device key, and an account alone grants nothing.

**P3-D4 (first card; C5).** The first card takes no session: a workspace login needs a card. It is
self-authenticating (the account `PK` signs the delegation, `WSK` signs the card). The first writer wins in one
transaction. Quotas are per owner account and per address, not per attacker-chosen workspace id. A captured genuine
card that wins first publication is the genuine card; the host then logs in with the same `WSK` and moves `card_seq`
on.

**P3-D5 (PK-only recovery; C6).**

- Revocations and device certificates are accepted without a session. Each is authorized by its `PK` signature
  alone, under strict per-address and per-person quotas.
- So a person who kept only the recovery code, and so `PK` (D50), can bootstrap: upload a new device certificate, log
  in with it, and revoke the lost device.
- The public record route reveals whether a known device id is revoked. §8 states this; login adds no further oracle.
- **Quota denial (challenge 2, finding 10).** Person quotas are charged only after the signature verifies, exact retries
  are free, windows are kept for their full duration (hour, day), never idle-pruned, and a reserved share stays
  available for revocations, so invalid or replayed submissions cannot block a recovery.
- (G0a review 5) Charge recovery/certificate person quotas only in the transaction that changes
  state. Verified expiry, revoked-device and superseded-revocation refusals, and exact retries,
  cost nothing. Do not charge first-card owner quota until both signatures verify.

### 19.2 Members and epochs

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/membership` | W(g) | `{member_list, grants: [wk_grant], card_key_wraps?: {card_seq, wraps}}` → `{list_seq, epoch}` | one transaction; the exact same body → 200; ≤ 1024 members, ≤ 2 MiB; JSON cap 2 MiB (G0a review 2) | 401 `bad_signature`; 403 `revoked`, `other_person`, `scope_exceeded`, `cert_expired`; 409 `other_workspace`, `stale_list`, `bad_epoch`, `rotation_required`, `wk_commit_changed`, `missing_grant`, `grant_conflict`, `stale_card`, `wrap_conflict` (G0a review 10), `fenced` | §7.2, §7.3 (P3-D7, P3-D26) |
| `PUT /v2/workspaces/{ws}/card-keys` | W(g) | `{card_seq, wraps: [{device_id, sealed}]}` → `{stored}` | only devices of the current list; same → no-op; JSON cap 64 KiB (G0a review 2) | 403; 409 `stale_card`, `wrap_conflict` (G0a review 10), `fenced` | §5.3 |
| `GET /v2/workspaces/{ws}/grants[?epoch=e]` | D(m) | → `{grants}` (own device, ascending, from `first_epoch` on) | | 403; 404 | §7.3 |
| `GET /v2/workspaces/{ws}/members` | D(m) or W | → `{member_list}` | | 403; 404 | §7.2 |
| `GET /v2/workspaces/{ws}/card-key?card_seq=N` | D(m) | → `{workspace_id, device_id, card_seq, sealed}` | | 403; 404 | host-api §3 |

**P3-D7 (atomic membership publication; replaces the rotation-abandon proposal; C8, C9).** A list, all grants for its
epoch and optionally the card-key wraps for new devices are published in **one request and one transaction**:

1. Every §7.2 check, with check 8 per P3-D6 and check 9 against the grants in the same body.
   (G0a review 1) Refuse 403 `other_person` if any `persons` entry lacks a member device.
2. The write-time re-check of each grant's and wrap's device certificate: stored, owned by the card owner or by a person
   in **this list's** `persons`, unexpired now, not revoked.
3. The write.

Consequences:

- **No staging deadlock for a new person (C8).** That person's grants are judged against the list that adds them.
- **No partial rotation state at the relay (C9).** A refused publication leaves nothing at an honest relay. The host
  still treats the body as possibly stored (G2b): it burns the epoch and `list_seq` and generates the next key at the
  next unused epoch (`EHW + 1`). **It never reseals a refused epoch**, and a burned key never seals anything (§7.2 H4).
- **The host persists `WK_E` durably before sending** (§7.2 H2). If the response is lost, it resends the exact body
  (idempotent).
- **If a committed key is lost anyway** (disk loss), the host treats it as host-state loss (§7.2 H7): it jumps its
  high-water marks by 1024 and rotates at once. Committed grants are never deleted until a later list replaces them.
- **`wk_commit_changed` (G2b).** A list at the held epoch with another `wk_commit` is refused: one `WK` per epoch.
  The relay cannot open grants; devices check them against `wk_commit` (§7.3 D3, D4).
- **The rotation-abandon route and label of orch-mobile's FakeRelay amendment are dropped.** Phones already accept
  forward epoch jumps.
- **`grant_conflict`.** Other bytes for an already-committed `(device, epoch)` are refused.
- **Retries (challenge 2, finding 11).** An exact-body retry of a committed publication returns its result before any
  freshness check. The host persists the sealed grants it sent and resends the same bytes, never reseals, so a retry
  never hits `grant_conflict`.

**P3-D6 (persons, D39; C8).** Each member entry is `{device_id, person_id, scopes}`, and the list carries
`persons: [person_id]` (sorted, unique). Check 8: the certificate's person is the card owner **or** in `persons`
(`other_person` otherwise). (G0a review 1) Every listed person must also have a member
device in this list; an unsupported person entry is 403 `other_person`.

The guarantee is narrower than F1:

- `persons` is the host's WSK-signed statement. It does not establish F1 roles; readers of the workspace log still
  replay `member.added` and roles.
- A WSK holder could add a foreign person. Such a holder can leak `WK` anyway.

In P3, lists have one person in practice.

### 19.3 Bridge, pairing and the `cert_pending` queues

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Proto |
|---|---|---|---|---|---|
| `POST /v2/workspaces/{ws}/bridge/{rid}` (device) | D(m) | raw ORB2, direction 1 → 202 `{}` | ≤ 1 MiB whole envelope; P3-D9 coalescing; budgets of P3-D17 | 400 `malformed`, `wrong_suite`; 403 `not_for_this_device`, `not_eligible`, `revoked`; 409 `rid_conflict`, `stale_epoch` (`epoch`), `retry_exhausted`; 429 `rate_limited` (G0a review 4) | §8.1, §8.9 |
| `GET /v2/workspaces/{ws}/bridge/{rid}?after=i&wait=s` (device) | D(m), own mailbox | → `{chunks: [{id, idx, last, stream, envelope}]}` | non-consuming | 401; 403 | §8.8 |
| `POST /v2/workspaces/{ws}/host/hold` | W | `{gen: int \| null, take_over: bool}` → `{gen, lease_s: 40, cursor}` | `gen` = the current generation: renews the lease, same `gen`; `gen: null`: a new generation when the lease is expired or `take_over` is set, otherwise 409; a stale `gen` → 409 `fenced`; JSON cap 16 KiB (G0a review 2) | 409 `holder_conflict`, `fenced` | P3-D10 |
| `GET /v2/workspaces/{ws}/host/poll?after=n&wait=s` | W(g) | → `{items: [{n, route, device, rid, offer, envelope}], notices: {revocations_cursor, cert_requests, rotation_due}, next}` | non-consuming; `after` acknowledges everything up to it (stored as `holders.cursor`); renews the lease; ≤ 16 items or 4 MiB | 409 `fenced`; 401 | P3-D10 |
| `POST /v2/workspaces/{ws}/bridge/{rid}` (host) | W(g) | raw ORB2, direction 2 → 202 `{}` | ≤ 256 KiB whole chunk; same `(device, rid, idx)` and bytes → no-op while a copy is live, stored again after it expired within P3-D27's bounds; other bytes → 409; epoch rule P3-D22 | 400; 403 `not_eligible`, `revoked`; 409 `chunk_conflict`, `stale_epoch`, `fenced`, `retry_exhausted` (P3-D27); 410 `expired` (G0a review 8, P3-D27); 429 | §8.1, §8.5, §8.9 |
| `POST /v2/workspaces/{ws}/pair/{offer}/{rid}` | none (device), W(g) (host answer) | raw epoch-0 ORB2 → 202 | ≤ 64 KiB; per workspace and per address (/64 IPv6) 60/min; /56 480/min (G0a review 9); global 6 000/min | 400; 401 `unknown_workspace`; 429 | §8.3, §8.9 |
| `GET /v2/workspaces/{ws}/pair/{offer}/{rid}?after=i&wait=s` | none | → `{chunks}` | per address (/64 IPv6) 120/min; /56 960/min (G0a review 9); global 12 000/min | 429 | §8.3 |
| `POST /v2/persons/{person}/cert-requests` | W(g), card owner = person | `{request}` → `{request_id}` | ≤ 1 open per workspace, ≤ 64 open per person; same → 200; JSON cap 64 KiB (G0a review 2) | 401 `bad_signature`; 403 `other_person`, `not_for_this_device`; 409 `request_open`, `replayed` | §8.4 step 1 |
| `GET /v2/persons/{person}/cert-requests?wait=s` | D(p), addressee only | → `{requests}` | open only | 403 | §8.4 step 2 |
| `POST /v2/cert-requests/{id}/challenge` | D(p), addressee | `{challenge}` → `{}` | `open` → `challenged` only; same verified `cj(o)` → 200 (G0a review 3); another challenge → 409; JSON cap 16 KiB (G0a review 2) | 401; 409 `replayed`; 410 `expired` | §8.4 step 3 |
| `POST /v2/cert-requests/{id}/rejection` | D(p), addressee | `{rejection}` → `{}` | `open` or `challenged` → `rejected`; same verified `cj(o)` → 200 (G0a review 3); JSON cap 16 KiB (G0a review 2) | 401; 409 `already_signed`; 410 | new (P3-D11) |
| `GET /v2/cert-requests/{id}` | W, the requester | → `{state, challenge, cert, rejection}` | kept until expiry + 60 s | 404 | §8.4 |

**P3-D8 (epoch at the relay; C10).** A device request for a **new** rid, whose header epoch is not the current list
epoch, is refused with 409 `stale_epoch {"epoch": current}`. This is an unsigned hint. The device:

- refetches the list and its grants (both signed);
- never raises its epoch from the hint;
- refetches at most 3 times per minute, then backs off 20, 40 and 60 s.

An **identical resend** of a known rid (P3-D9) skips the epoch check, so the host can answer from its rid store with the
stored bytes. The relay's order is: session and membership → shape → replay store → epoch.

**P3-D9 (replay store and coalescing; C11).** The relay keeps `(ws, device, rid)` for 900 s from the **first** receipt.
A resend never extends this; the only exception is that the record lives on until every dependent queued message has
expired (`keep_until_ms`):

- **Same bytes:**
  - If an unexpired undelivered copy exists (its `n` is above the holder's acknowledged cursor and now is before its expiry; G0a review 7), the resend is coalesced: 202,
    nothing new queued.
  - Otherwise it is queued again, at most once per 10 s and at most 8 times per rid. After that cap the relay answers
    409 `retry_exhausted`, so a device never takes a 202 for a delivery promise (challenge 2, finding 9). A new copy
    lives 60 s from its own receipt, and the `rid_seen` and `rid_chunks` rows are kept until every dependent message
    has expired, so conflict detection never ends before them. Records and chunk digests are bounded per device
    (P3-D17).
- **Other bytes:** 409 `rid_conflict`.

The relay never checks `seq` or `ts_ms`: the host's sealed refusals do that. The host's durable rid store stays the only
exactly-once authority.

**P3-D10 (durable host cursor and fencing; C12).** This replaces the consuming poll:

- **Hold.** The host first takes a holder generation `gen` (`host/hold`). A new generation needs an expired lease or
  an explicit `take_over` (no silent automatic takeover). The lease is 40 s; the host renews it every 15 s, by a poll or
  by `host/hold` with `gen` set to its current generation.
- **One live poll per generation.** A new poll cancels the previous one of the same `gen`.
- **Compare-and-set (challenge 2, finding 8).** Every cursor move and every host write is a compare-and-set on
  `(gen, lease unexpired)`, re-checked after a long-poll wakeup before data is handed over.
- **Fencing.** Every host write carries `Orch-Holder: gen`: response chunks, pair answers, membership, card, card keys,
  cert requests. A stale generation is 409 `fenced`, so an old host process that wakes up after a
  takeover cannot interleave writes.
- **Delivery.** The poll is non-consuming: items have a strictly increasing `n` and stay until their 60 s expiry. The
  host passes `after` = the end of the **contiguous prefix** of items it has durably completed (recorded in its rid
  store), never the highest `n` seen; the relay moves the cursor only forward. A lost HTTP response is harmless: the
  next poll returns the same items. Delivery is **at-least-once within the 60 s retention**; later, the device's
  resend is the recovery.
- **Authorization at handoff.** The relay filters each item against membership and revocation in the same transaction
  that reads it. Devices' response polls do the same.
- **Limit.** Fencing protects an honest host from its own stale twin. It does not protect against a WSK holder, who
  can always take over (design §8).

**P3-D11 (cert queues; C13).** One transactional state machine per request:

- **States:** `open` → `challenged` → `signed`; `rejected` from `open` or `challenged`; `expired` from any non-terminal
  state at `expires_ms`.
- **Validation.** The relay verifies the request under the card's `WSK`, and the challenge and the rejection under
  the account's `PK`.
- **No replacement.** It refuses to replace a challenge.
- **When the request becomes `signed`.** Only when a certificate is stored (`PUT devices`) whose `dk_sig_pub`,
  `dk_kx_pub`, `device_id` and person equal the challenge's. Scopes are inside the sealed inner request, so the host
  checks them, not the relay.
- **Rejection** is a new signed kind, `cert_rejection {v, suite, kind, request_id, workspace_id, person_id}`, under
  `orch/v2/sig/cert-rejection|`.
- **FakeRelay change.** The primary must now use a device session; its session-less submission in the FakeRelay
  changes.

**P3-D16 (scopes).** On the bridge the relay enforces membership only. Ops and scopes are sealed. The typing lease has
no relay part.

**P3-D22 (old-epoch responses; C19, Q10; challenge 2, finding 13).** A defence against honest-host mistakes, not a
confidentiality boundary against a malicious host (the relay sees a flag, not the sealed refusal). A response chunk's
epoch must equal its request's (`rid_seen.req_epoch`), and the chunk must answer a known request (rid). Once the list
epoch has moved past that epoch, the relay accepts an old-epoch chunk only if it has the `LAST | REFUSAL` shape, or if it
is byte-identical to a chunk already accepted for that rid (a stored replay, `rid_chunks`). An unknown or expired rid is 410 `expired` (G0a review 8). Other epoch violations are 409
`stale_epoch`. The device validates the refusal itself (§8.8). Replaying stored bytes never extends a live chunk's
TTL, and an expired old-epoch data chunk is never stored again (P3-D27). This cannot constrain a compromised relay.

**P3-D27 (bounded exact-bytes re-store; Q11).** A host replays an answer as the exact chunk bytes it already
posted (§8.6 step 5); v1's re-seal could never pass `chunk_conflict`. When a byte-identical chunk arrives for a
known `(device, rid, idx)` and no unexpired copy of it is queued, the relay stores it again with a fresh 60 s TTL,
subject to all of these:

- **Gates first.** Holder fencing, the target device's eligibility (current member, not revoked, certificate
  unexpired) and `chunk_conflict` run before this rule, as for a new chunk. A chunk posted by an old holder
  generation, or to a device since removed or revoked, is no authorization to store it again.
- **Epoch.** Only a chunk at the current list epoch, or one with the `LAST | REFUSAL` shape. An expired
  old-epoch data chunk stays expired: 202, nothing stored (P3-D22). The device then ends `uncertain`.
- **Deadline.** Only before `rid_seen.first_ms + 900 s`, an immutable deadline from the first receipt; never the
  extended `keep_until_ms`. After it: 410 `expired`.
- **No extension.** The copy expires at `min(now + 60 s, keep_until_ms)`. A re-store never changes
  `keep_until_ms`, so chunks restored in turn cannot keep a rid alive.
- **Cap.** At most 8 restorations per chunk, counted durably (`rid_chunks.restores`; survives a restart). The
  ninth is 409 `retry_exhausted`, terminal. The 64-chunk ceiling per rid is unchanged.
- **Budgets.** A re-store is charged to the host-post rate and the response storage budgets (P3-D17); 429 and
  503 apply as for a new chunk. A live duplicate stays a free no-op that never changes its TTL.
- **Pairing answers** (the `pair` route) are never stored again.
- **Removal.** Removing a device from the workspace (or revoking it) sets its chunks' restoration count to the
  cap. The rows and digests stay, so `chunk_conflict` still holds, and a re-added device gets nothing
  restored (409 `retry_exhausted`).
- **Order.** The epoch rule precedes the deadline (expired old-epoch data past it is a 202 no-op, not 410);
  the cap precedes the rate and budgets (a capped chunk is 409 and spends nothing).

The device side is in §8.8 (the 240 s resend bound, the `stale_timestamp` offset). This changes only what an
honest relay stores: a hostile relay could always replay bytes it once held. Vectors: `p3.restore`.


### 19.4 Authentication and budgets

**Login** is §12.2 unchanged:

- The signed bytes are `"orch/v2/sig/relay-auth|" || suite || lp16(origin) || challenge || kind || id`.
- `origin` is the instance's configured origin (`ORCH_RELAY_ORIGIN`), never one the client names.
- Check order: the challenge is known (and removed whatever follows), unexpired, a valid `kind`, then the signature.

**Unknown ids** are verified against a fixed dummy P-256 key: same timing, the same 401 `bad_signature`, and the
challenge is consumed. (G0a review 10) Even a signature that verifies under the dummy key MUST
return 401. Production MUST generate a per-instance random dummy public key and discard its
private half; the publicly derived reference key is only a test artifact.

**Revoked devices get no session** (the owner's decision):

- The answer is 403 `revoked`, and only after the signature verifies.
- An expired certificate gets 400 `cert_expired`.
- The device reads its record session-less and verifies it under its pinned `PK` before wiping.

**P3-D2 (sessions; C4).**

- **Lifetime.** Bearer tokens last 15 minutes, with no refresh. A new login never invalidates other live tokens:
  clients reauthenticate single-flight and may overlap tokens. (G0a review 10) At most eight
  unexpired tokens per device across all sessions; additional logins return 429 `quota_exceeded`
  with Retry-After until the earliest expiry. Consume the challenge, preserve existing tokens.
- **Every route re-checks** expiry, revocation and certificate expiry against the database at request time. Long polls
  re-check immediately before handing over data, not only every few seconds.
- **Scope.** A device token is scoped to the relay; each workspace route authorizes against the current list. A
  workspace token is scoped to its workspace.
- **Tokens are stored as SHA-256 hashes.** That protects a database dump. It does not make a stolen bearer useless:
  a stolen token works until it expires or the device is revoked (design §8).
- Agents never see tokens (spec §5.5).

**P3-D17 (budgets; C7).** All limits are refusals, never evictions of existing state:

- **Challenges:** 16 outstanding and 60 per minute per address. The global ceiling of 65 536 outstanding is a refusal
  (429), never the eviction of other clients' challenges.
- **Per device, across all its sessions:** ≤ 128 live request mailboxes per workspace, 20 posts/s, 6 concurrent long
  polls, ≤ 8 MiB of queued requests.
- **Per workspace:** ≤ 1 024 queued requests, ≤ 16 MiB queued requests, ≤ 16 MiB undelivered responses. (G0a review 10) Each device may consume at most
  2 MiB of that response budget across its sessions; excess is 429 `quota_exceeded`, without eviction.
- **Global:** ≤ 256 MiB of queued bodies and ≤ 4 096 concurrent long polls (503 `overloaded`).
- **Anonymous pair long polls (G3 review 2/3):** ≤ 4 concurrent per canonical client address, ≤ 32 per
  IPv4 /24, ≤ 32 per IPv6 /56 and ≤ 64 per IPv6 /48 (429 `quota_exceeded`), and ≤ 512 in total, a
  separate share of the 4 096 (503 `overloaded`). At most 16 pair polls wait on one
  `(ws, offer, rid)` (429 `quota_exceeded`).
- **Authorization first (G3 review 3):** every bridge, pair, holder and certificate request is
  authenticated, authorized and fenced by a read-only check before it takes the directory lock, a
  write transaction, a rate window, a poll slot or a wakeup; only anonymous pairing is admitted
  without a session, and it is charged only to its own windows. Refusal codes match the
  transaction's, with one deliberate exception: a non-device session posting a cert challenge or
  rejection gets 403 `not_eligible` before the request lookup, even for an unknown request id
  (never 404), so it learns nothing about request ids. Host pair answers use separate
  pairing windows with the same caps, and host response chunks are rate-limited per (workspace,
  target device), never against the device's own 20 posts/s.
- **Waiting long polls** hold no lock, transaction or worker thread. Commits that insert or change
  rows wake only the affected polls (new requests → that workspace's host; responses → that rid;
  revocation, logout, certificate store → that device's polls and the hosts of its workspaces;
  membership → that workspace). Each poll also re-checks at its session/certificate expiry and on a
  jittered 5–7 s tick, using a read-only check on the event loop; only a ready or refused check
  re-runs the full fenced transaction. At the deadline host polls rebuild their response with the
  transaction; device, pair and cert polls re-check on the event loop and answer empty unless ready
  or refused. Waits of 5 s or more end up to 10 % (≤ 1 s) early, so polls admitted together do not
  time out together. Identical resends and replays wake nobody.
- **Host poll notices** make a poll ready only when they differ from the notices last delivered to
  the current holder generation (a new generation receives them once); a past revocation alone does
  not keep a host poll from waiting.
- **Client addresses.**
  - The peer address is used, or Caddy's `X-Forwarded-For` only when the peer is the configured proxy.
  - Addresses are canonicalized: IPv4-mapped IPv6 becomes IPv4, and IPv6 is grouped by /64.
  - Windows are kept for their full duration (minute, hour, day) and pruned only after it ends; per-person windows
    are charged only on verified state changes (§19.1 P3-D5; G0a review 5).
- **Per device:** at most 4 096 `rid_seen` records and 64 chunk digests per rid.


(G0a review 9) IPv6 challenge and pairing limits are hierarchical: enforce the existing /64
limits AND a /56 aggregate. Each /56 permits at most 256 outstanding login challenges and
960 new challenges/min; pairing permits 960 GET/min and 480 POST/min. The existing global
challenge and pairing limits still apply. A distributed attacker spanning enough /56 networks
can saturate the global limits and temporarily lock out honest clients; this remaining global
saturation is an accepted limit of this contract. Do not evict existing state.

### 19.5 The relay side of revocation (#12, §6.2)

On a verified revocation, from the revocation route, the relay does the following in one transaction:

- it stores the revocation, or upgrades the stored reason (compromised over lost/retired);
- it deletes the device's sessions, request mailboxes, queued responses, grants and card-key wraps in every workspace;
- it refuses the device on every route;
- it sets `rotation_due` for each workspace whose current list names the device.

`rotation_due` is durable: one row per obligating device, with the revocation's cursor and epoch. It is cleared only by
a committed list with a higher epoch that excludes the device, in a transaction serialized with revocation intake, so a
newer obligation is never cleared by an older publication. The host sees it in its poll until then. There is no
un-revoke.


### 19.6 Exact HTTP shapes and common refusals (P3-D1/D2/D10/D17)

`tests/http_fixtures/*.json` is the executable example corpus (one file per route role).
`tests/http_fixtures/MANIFEST.json` lists the sha256 of every other file in that directory plus an
aggregate hash (`uv run python tests/http_fixtures/manifest.py --write|--check`; a pytest fails on a stale
manifest). Bump `revision` whenever any fixture changes. Consumers (orch-mobile, orch-core) vendor the
corpus at a named commit and verify the manifest in their CI.
There are no public invite-management routes: invite creation is the admin CLI (P3-D3).
Checkpoint, restore, genesis, staging, baseline and proof routes are specified in §19.8 (P3-D12/D13/D18–D25).

Requests and responses use `application/json`, except ORB2 posts (`application/octet-stream`).
JSON field sets shown above are exact. GET requests have no body. Empty success bodies are `{}`,
including 202. Bearer authorization is `Authorization: Bearer <token>`; `Orch-Holder` is a decimal
generation. The first card is the only unfenced workspace write. Logout returns 200 for an
unknown/expired token as well as an already-logged-out token.

All routes can refuse 400 `malformed` for invalid fields, paths, query or strict JSON; bounded
JSON requests refuse 413 `too_large` before parsing (G0a review 2), except the P3-D20 final checkpoint request (400); bounded ORB2 requests
retain 400 `too_large`. Authenticated routes can refuse 401 `unauthenticated`.
(G0a review 6) Only D sessions can fail session checks with 400 `cert_expired` or 403 `revoked`;
W sessions have no device certificate. Membership uses only 403 `cert_expired`, because the
expired certificate is a proposed member's, not the W session's. Target-device revocation checks
on membership and host bridge posts still apply. A wrong principal or inaccessible workspace/person is
403 `not_eligible`. W(g) routes additionally refuse 409 `fenced` for missing, stale or expired
holder authority. Signature objects of another deployment suite are 400 `wrong_suite`.
Route-table bare statuses mean: 400 `malformed`, 401 `unauthenticated`, 403 `not_eligible`,
404 `not_found`, 410 `expired`, 429 `rate_limited` or `quota_exceeded`. Rate windows return
429 `rate_limited`; storage/concurrency caps return 429 `quota_exceeded`; shared global bridge
budgets return 503 `overloaded`. Each 429/503 includes integer delta-seconds `Retry-After`.
Challenges' global cap specifically uses 429 `rate_limited`.

Identifiers are lower-case 16-byte hex, except §19.8 checkpoint hashes, log accumulators and ticket ULIDs; binary JSON values (including ORB2 poll envelopes,
challenges, public keys and signatures) are canonical b64u. All positions fit JSON's safe integer
range. `wait` is an integer 0..25, default 0. Omitted `after` starts before the first item
(including chunk index 0); supplied positions are exclusive non-negative decimal integers.
Revocation feed `limit` defaults to 256; each entry is `{cursor, record}`, ascending cursor.
Host poll `next` is null at end, otherwise an opaque continuation passed as `next` with the
same `after`; it never acknowledges items. A poll's `after` acknowledges only the host's
contiguous durably completed prefix and cannot exceed the highest delivered position. Invalid
forward acknowledgements are 400 `malformed`; older cursors never move the stored cursor back.
A cancelled same-generation poll returns an empty success; it cannot later deliver stale data.

Host poll `route` is `bridge` or `pair`; `offer` is null for bridge and the offer id for pair.
`notices` is exactly `{revocations_cursor, cert_requests: [request_id],
rotation_due: [{device_id, revocation_cursor, epoch}]}`; arrays are sorted by id. The cursor
is the latest relevant revocation-feed position (0 if none). `cert_requests` lists requester
records with challenge/rejection/certificate results to fetch. Cert-request GET always returns
all four fields `{state, challenge, cert, rejection}`, using null when absent.

(G0a review 4) (ambiguity 10) During P3-D9's ten-second requeue interval return 429
`rate_limited` with `Retry-After` equal to the remaining interval rounded up to integer seconds.
409 `retry_exhausted` is terminal, only once eight requeues have been used (excluding the first
receipt), when no unexpired undelivered copy remains. After a 202 or 429 the device MUST keep
polling its mailbox for that rid and MUST NOT automatically reissue the operation under a new
rid. Terminal exhaustion also MUST NOT trigger automatic reissue under a new rid; continue
polling for a queued response while retained, then surface failure for explicit user resolution.
(G0a review 8) (ambiguity 11) P3-D22 returns 410 `expired` for an unknown or expired response rid.
A stored chunk replay with a live copy returns 202 without refreshing its TTL. An expired identical chunk is
stored again only within P3-D27's bounds (current epoch or `LAST | REFUSAL`, before first receipt + 900 s,
at most 8 times, never past `keep_until_ms`); expired old-epoch data is a 202 no-op.
If a matching known chunk index has different bytes, `chunk_conflict` precedes the epoch rule.
`LAST | REFUSAL` may also carry `STREAM`; a refusal always has LAST.

Exact-body idempotency means identical HTTP bytes. Send `cj(body)` and persist it. Signature
verification always uses `cj(o)` independently of HTTP whitespace. Membership retries still
require current session and holder authorization, but skip certificate/list/card freshness.
P3-D7 grant checks bind workspace/device/epoch, exact field set and signature; sealed bytes
are opaque but must have the §5.3 suite framing and valid ephemeral public key. Wraps have
the same framing check. A malformed grant/wrap is 400 `malformed`, bad grant signature is
401 `bad_signature`, a grant outside this publication is 403 `not_for_this_device`.

P3-D11 request signature/shape/context precede insertion. Open means open or challenged and
unexpired, for quota purposes. Request and challenge times use §8.4. Context mismatch is
403 `other_person` (person), 409 `other_workspace` (workspace), or 403 `not_for_this_device`
(request/addressee). Invalid certificate keys in a challenge are 400 `malformed`.


### 19.7 Implementation notes and orch-mobile changes

(G0a review 10) Keep exact membership publication digests and results scoped per workspace
for seven days from acceptance (retries do not refresh retention). After a lost response and
`stale_list`, the host MUST GET the signed members and compare with its persisted publication.
If equal, treat publication as accepted. If a newer list exists, reconcile it and publish using a
fresh sequence/epoch under §7.2; never replay an older list over it. If acceptance cannot be
established, surface a conflict rather than assuming success.

(G0a review 10) For both membership `card_key_wraps` and `PUT card-keys`, an identical wrap
for `(device, card_seq)` is an idempotent no-op; different sealed bytes for that pair return
409 `wrap_conflict`, atomically with no partial writes. A newer card sequence may replace the
older wrap. Hosts MUST persist wraps before sending, as they do grants.

(G0a review 7) Same-card identity includes `sealed_hash` and `ck_commit`; identical sequence
with different sealed content is 409 `stale_card`. Certificate completion MUST compare both
`dk_sig_pub` and `dk_kx_pub`. Accepted publication MUST prune grants and wraps for departed
devices. Boundary limits remain 64 certificates/day, 64 open requests/person, 64 chunks/rid,
900-second rid retention (extended only for dependent messages), and ten-minute cert requests.

**orch-mobile changes (G0a review 11).** Stream C MUST update FakeRelay and the adapter:

- Parse/sign the new member-list `persons` and per-member `person_id`; enforce the directory
  admission and historical-device filtering rules (G0a review 1).
- Replace staged grants with atomic membership publication; remove the abandon route.
- Require the primary's device session and PK-signed `cert_rejection`.
- Handle `retry_exhausted`, `stale_epoch` with bounded signed-list/grant refetch, and `not_visible`.
- Coalesce only live undelivered copies; do not refresh mailbox TTL on retries.
- Use the `/v2` routes without `host_api` or `Orch-Host-API`.
- Accept re-signed identical canonical certificates/challenges/rejections as idempotent (G0a review 3).
- Distinguish interval 429 + Retry-After from terminal 409; keep polling the same rid after
  202/429 and never automatically reissue under a new rid (G0a review 4).
- Enforce JSON caps/413, state-change-only quotas, auth-class refusals, unknown-rid 410,
  wrap conflicts, token and response budgets, and hierarchical IPv6 caps as specified above.

**orch-mobile changes (G2b, P3-D26).** FakeRelay's `checkSequence` (the relay publication rules) becomes, given
the previous accepted list `p` (or none):

| Input | Result |
|---|---|
| shape: `wk_commit` missing, not a string, not canonical b64u, or not 32 bytes; `epoch` outside `1 … 2^32−1` | 400 `malformed` |
| no previous list, `1 ≤ epoch ≤ 2^16`, any `list_seq ≥ 1` | accept (a refused first publication retries at `(2, 2)`) |
| no previous list, `epoch > 2^16` | 409 `bad_epoch` |
| `list_seq ≤ p.list_seq` | 409 `stale_list` (gaps above are fine) |
| `epoch < p.epoch` or `epoch > p.epoch + 2^16` | 409 `bad_epoch` |
| a member of `p` missing and `epoch ≤ p.epoch` | 409 `rotation_required` |
| `epoch == p.epoch` and `wk_commit ≠ p.wk_commit` | 409 `wk_commit_changed` (new code) |
| otherwise | continue with checks 8 and 9, unchanged |

The order is the relay's: shape, `other_workspace`, `stale_list`, `bad_epoch`, `rotation_required`,
`wk_commit_changed`, then grants and certificates. `MemberList` parses `wk_commit` (field set), FakeHost
`discardRefused` keeps `wks[p.epoch]` as a retained, never-activated key and raises its `listSeq` and epoch
floors to the refused body's, rotating next at `floor + 1`; on `stale_card`/`wrap_conflict` it resends the same
signed list and grants. Devices implement §7.3 D1–D4 and the `wk_commit_conflict` alarm. Vectors:
`member_lists`, `member_list_snapshots`, `wk_commit`; fixture `membership.json` (`refusal_409_wk_commit_changed`).


### 19.8 Checkpoints, genesis and restore transport (P3-D12/D13/D18–D25)

This section uses F1 §5.3/5.6/5.10 at orch-core `4f00d9ce32e8e512366c908c36b43f35142747c9` (develop, the merge
of orch-core #377: receiver vectors with an explicit receiver view, `Verdict` with alarms, honest recovery for a host
that lost its checkpoints). The relay's F1 vector snapshot `tests/vectors/f1` pins the same commit, and
`tests/vectors/f1_receiver_4f00d9c.json` extracts its receiver cases (88 `transition_cases`, 30
`workspace_n_offers`, sha256 of the source file recorded), which run unchanged against the reference device judge.
The earlier extracts (f1094b3, and orch-52's unmerged branch head) are retired: every case they carried is in the
merged set. Each shared case gives the receiver's whole view: its clock `now`, the `pinned_delegation`,
`known_devices` (every device it knows, active or revoked, with its person and optional key), `known_revocations`
(held when judging) and `learned_later_in_walk`. `known_devices` is a required input of the judge (orch-core B1):
an empty map says the receiver knows no device, and a missing one is an error, never "nothing known".
F1 defines event/checkpoint bytes; the relay adds storage, transport and present-authority checks.
**P3-D12:** only `workspace_checkpoint` objects are published, never `ticket_checkpoint` objects.

| Method, path | Auth | Request → response | Idempotency, limits | Refusals | Decision |
|---|---|---|---|---|---|
| `PUT /v2/workspaces/{ws}/genesis` | W(g) | `{pin, cert}` → `{}` | JSON cap 64 KiB; once, identical pin is a retry | 401 `bad_signature`; 409 `genesis_mismatch`, `restore_not_owner` | P3-D18 |
| `PUT /v2/workspaces/{ws}/staging/{source_hash}/{target_hash}/pages/{i}` | W(g) | `{kind, log, after_seq, from_acc, heads, digest}` → `{}` | JSON cap 4 MiB; immutable page; 1 h set expiry | 409 `staging_conflict`; 429 `quota_exceeded` | P3-D20 |
| `PUT /v2/workspaces/{ws}/staging/{source_hash}/{target_hash}/manifest` | W(g) | `{pages: [{i, kind, log, after_seq, count, digest}]}` → `{complete, missing}` | JSON cap 4 MiB; immutable terminal marker | 409 `staging_conflict`; 429 `quota_exceeded` | P3-D20 |
| `POST /v2/workspaces/{ws}/baselines` | W(g) | `{hash, offer_id}` → `{until_ms}` | JSON cap 16 KiB; 7 days, at most 16 pins | 404 `not_found`; 410 `checkpoint_gone`; 429 `quota_exceeded` | P3-D13/D20 |
| `DELETE /v2/workspaces/{ws}/baselines/{hash}[?offer_id=o]` | W(g), or D(m) after initialization naming `offer_id` | no body → `{}` | idempotent release; W(g) releases any pin, D(m) only the pin whose `offer_id` it names, otherwise a no-op | — | P3-D13/D20 |
| `PUT /v2/workspaces/{ws}/checkpoint` | W(g) | `{checkpoint, source_hash, restore?}` with `restore = {line, cert, authz, log}` → `{result: "accepted" or "ignored", n, hash}` | JSON cap 2624 KiB; atomic; exact retry returns prior result; `Orch-Holder` required; at most 16 refusals per holder generation and 48 per workspace in any rolling hour | 400 `wrong_suite`, `too_large`; 401 `bad_signature`; 409 `fenced`, `no_genesis`, `genesis_mismatch`, `chain_diverged`, `checkpoint_time`, `staging_incomplete`, `restore_invalid`, `restore_not_owner`, `restore_source_mismatch`, `restore_reused`, `restore_missing_revocation`; 429 `quota_exceeded` | P3-D13/D20/D24/D25 |
| `GET /v2/workspaces/{ws}/checkpoint[?hash=h]` | D(m) or W | `{genesis: {pin, cert}, checkpoint, transitions_head}` | held H or immutable hash h | 404 `not_found`; 410 `checkpoint_gone` | P3-D18/D19 |
| `GET /v2/workspaces/{ws}/transitions?after_n=k&to=E&limit=` | D(m) or W | `{transitions: [bundle], next}` | ascending target_n; default/max 16, at most 4 MiB | 404 `not_found`; 410 `checkpoint_gone` | P3-D13/D19 |
| `GET /v2/workspaces/{ws}/proof?log=L&from=acc&to=E&limit=` | D(m) or W | `{heads: [head], next}` | default/max 65 536, at most 4 MiB | 404 `not_found`; 410 `checkpoint_gone` | P3-D19 |

Common §19.6 refusals and holder fencing apply. The checkpoint's **object** cap is 2 MiB of `cj`
bytes. The restore event is at most **524,288 bytes including its LF**, measured as the complete signed
F1 line. The whole final request is at most **2 MiB + 524,288 + 64 KiB = 2,686,976 bytes**.
An over-cap request is 400 `too_large` on this route (P3-D20, specific exception to §19.6's JSON 413);
an over-cap checkpoint or line is also 400. Other new JSON routes use 413 before parsing.
Revocation evidence is never truncated. Hosts refuse `ticket.created` at 1.8 MiB (`checkpoint.capacity`,
a local host error), before storage approaches the hard limit. About 5 000 tickets remains the conservative
advertised capacity pending deployment measurements. Fold work and `log_nodes` storage are O(history).

**Genesis (P3-D18).** An owner device signs
`{o: {v:2, suite, kind:"genesis_pin", workspace_id, wsk_pub, genesis}, sig}` with
`sig_genesis_pin || cj(o)`. First acceptance checks the card's owner PK, certificate binding,
`operate` scope, expiry at the relay clock, non-revocation, workspace and card WSK. The relay refuses
checkpoints without this pin or with a different genesis. An established pin is never replaced, including
after certificate expiry/revocation; revocation raises an alarm. Devices verify it historically under the
pairing-pinned owner PK. The pin attests genesis; only hosts with the log validate `workspace.created`.
**Accepted limit (review 9):** a WSK holder with a stolen, not yet revoked owner device can pin a wrong genesis
before the honest host's first link. Every later checkpoint is then `genesis_mismatch`; revocation only raises the
alarm. This is a denial of service, not a rollback (devices verify the pin under the pairing-pinned PK), and its
recovery is a new workspace. An owner-PK-signed re-pin is deferred to P8.

**Ancestry (P3-D19).** Each log entry is exactly `{seq, head, acc}`. `acc_0` is 32 zero bytes;
`acc_k = H(h_log_acc || raw32(acc_{k-1}) || raw32(head_k))`, encoded as `sha256:` plus 64 lowercase hex.
Neither text encodings nor seq are in the preimage. Growth requires exactly `t-s` heads, ending at the signed
head and folding to the signed acc. Equal seq requires identical head and acc. Every existing log remains.
`h_checkpoint(C) = H(h_checkpoint-label || cj(C.o))`, in the same hash-string encoding; signatures are excluded.
Checkpoints use `sig_checkpoint || cj(o)`, with F1's exact workspace object shape and whole-second UTC `at`.
Equal n requires the same object. A lower n is ignored only when no offered entry is new, higher, or conflicting
at equal height. It never advances H. Higher n must also satisfy the position-time rules below.

The relay retains immutable branch-agnostic `log_nodes(workspace, log, acc) → (seq, head, prev_acc)`.
Restores do not delete abandoned nodes. Reads walk backwards from **the requested checkpoint's** acc,
then return heads in forward order. A proof's source acc must be on that branch. This catches abandonment
of a receiver's committed prefix with an honest host and withholding relay; it does not establish event
validity, latestness or disclosure of every restore. A WSK holder can fabricate accumulators.

**Staging and atomicity (P3-D20).** The set is bound to `(source_hash, target_hash)`; null source is spelled
`null` in the path. `kind` is `appended`, `abandoned` or `retained`; `log` is `workspace` or a ticket ULID.
`appended` proves ordinary growth; `abandoned` proves the source suffix above `from_seq`; `retained` proves
the retained endpoint from a held node. Omit retained pages when the relay already holds the path.
The manifest lists every page, sorted by `(kind, log, after_seq)`, with unique nonnegative page indices and
contiguous ranges within each kind/log. Its descriptors must match page metadata, counts and digests.
Pages are nonempty and at most 4 MiB each. Identical retries are no-ops; different HTTP bytes at an existing
index or a different terminal manifest is `staging_conflict`. A manifest may precede missing pages and
returns their indices. An unlisted page is a conflict. At most two live sets and 64 MiB of page and manifest
bytes are allowed per workspace. A deployment also enforces a global ceiling on staged bytes across workspaces
(default 4 GiB; 503 `overloaded` beyond it, never an eviction); the reference models one workspace and does not
exercise it. Expiry is one hour from set creation, never extended by retries.
Final publication requires the manifest and every listed page (`staging_incomplete` otherwise), validates
every fold, all sizes and R0–R5 before effects, and rejects unused evidence. The transaction persists nodes,
revocations, the transition and checkpoint, then advances H together. Refusals record no restore IDs.
**Failure budget (review 3, amended N5).** A refused final publication is charged only after the request passed
W(g) authentication and the holder-generation check: a 401 or a 409 `fenced` (stale holder) is never charged.
The `Orch-Holder` generation is required (a missing one is 400 `malformed`, uncharged). Each holder generation
may spend at most 16 refusals per rolling hour, so a compromised former holder cannot use up its successor's
slice; across generations the workspace is capped at 48 refusals per rolling hour (review F1). Takeovers are not
rate limited, because P3-D10 lets a WSK holder (and an honest host restarting after a crash) always take over; the
workspace ceiling is what bounds a WSK holder that takes over from itself repeatedly. Accepted cost: a WSK holder
that takes over three or more times an hour can keep the 48 refusals full, and then valid publications are also
429 until the window frees. This adds no power, since a WSK holder can already deny service by fighting over
the lease (P3-D10); the remedy for a hostile WSK holder is rotating the WSK. Order: size cap and parse, then
an exact retry of an accepted publication returns its stored result (also with the budget spent), then the budget
check (429 `quota_exceeded`, not charged), then signature and fold work. `ignored` lower-n publications are not
charged; they cost one signature check and one canonicalisation of at most 2 MiB.

**Restore rules (P3-D13/D23/D24/D25).** `restore` is `{line, cert, authz: {delegation}, log}`.
`line` is the full F1 event object, with its payload fields at the top level, not an interim nested payload.
`log` is `workspace` or the restored ticket's ULID; it is required (review 3), and the relay verifies the signatures
in that one context only, never by trying T's entries.

- **R0 (P3-D13):** exact F1 restore fields, person actor, `v=2`, `hash_v=1`, `sig`, `auth`, `roster_v`,
  `host_sig`; `ws_seq` exactly when `log` is a ticket. Strict JSON, schema and line-size checks precede effects.
  The bundle's delegation MUST have the card's delegation content (`o` equal) and verify under the owner PK (card
  binding; orch-core #377: an owner re-signing the same content is the same delegation).
- **R1 (P3-D24):** verify both host and person signatures using F1's `{workspace_id, log}` context.
  Verify the card's PK-signed delegation and PK-certified device; actor person/device IDs must match,
  scope levels include operate and no `drop:` scope. Certificate validity is checked at `line.at` and,
  by the relay only, at its present clock; the signer is unrevoked by every revocation the relay holds and by
  evidence in this payload, and currently in the relay member list with operate. Missing authorization evidence
  is refused.
- **R2 (P3-D13):** person-signed `source` equals `{n: H.o.n, hash: h_checkpoint(H)}`;
  outer source_hash must agree. Null is allowed only when no H exists. A withheld old restore or the
  losing member of two concurrent restores against one source needs a newly signed source.
- **R3 (P3-D13/D19):** `line.seq = from_seq+1`, `line.prev = head`, `from_seq >= 1`.
  Prove that the retained endpoint actually ends in the owner-signed head. Below C's seq, the staged
  abandoned suffix must fold from acc_from to C, with exact count; a retained page starts at a stored
  node on C's branch. At/above C's seq, prove the forward path. Zero-length proofs compare the endpoint
  head and acc directly. T's restored entry is exactly `{from_seq+1, head(line), fold(acc_from, head(line))}`.
  Other logs extend C with exact appended evidence; no log disappears; T.n>C.n; ticket ws_seq does not
  exceed T's workspace height. Signed abandoned must cover C when C is above from_seq; an equal-height
  conflicting abandoned head is refused.
- **R3a (P3-D25):** `C.o.at <= line.at <= T.o.at`, `T.o.at >= H.o.at`, and
  `T.o.at <= relay clock + 300 s`. The two constraints on T itself apply to every publication, restores included,
  with 409 `checkpoint_time`, at the relay and on the device alike (inclusive at +300 s). A `line.at` outside
  `[C.o.at, T.o.at]` is 409 `restore_invalid`. There is no separate ceiling on `line.at`: past the ceiling it is
  either `checkpoint_time` (T is too) or `restore_invalid` (`line.at > T.o.at`) (review F7).
  The host clamps checkpoint at to max(clock, previous at), and restore at to max(clock, source at,
  last merged-order at). `at` is a host-chosen position, not a person-signed timestamp. Rewriting it
  within the anchored window remains possible and is explicitly tested.
- **R4 (P3-D13, F1 B1):** workspace restores carry all effective host-held revocations; ticket restores
  carry `[]`. Validate every `{revocation, device_cert, pk_pub}` first; the certificate's `person_id` must equal
  `H(h_person_id || suite || pk_pub)`. **Device binding (review N1/F3, as F1 `model/workspace.restore`):** the
  relay binds a device to a person authoritatively from its global device registry (§19.1/§6.2, live at check
  time, so a member added later is bound) or from a restore signer it verified under the owner PK; the person's
  key is the directory account key. **The first accepted binding wins (review A/B):** a device whose revocation the
  relay holds is bound to that revocation's person, ahead of any registry entry (its key is fixed by
  `person_id = H(pk_pub)`). Evidence for a bound device MUST carry that person and key. Only a wholly unknown device (an
  abandoned-only or v1-imported member's) is accepted self-certifying (review 5); in the same transaction the
  relay registers that device's certificate in the global device registry and records the revocation through
  §19.5 intake, so a later `PUT /v2/devices/{device}` for the key is 403 `revoked` (or 409 `cert_conflict`) and the
  registry can never contradict the binding. A held revocation is never deleted (§6.2 "no un-revoke"), whatever
  the registry later says. Accepted consequence: if a malicious WSK host gets an owner device to sign a restore
  carrying another person's evidence for an owner device the registry does not know yet, that device stays bound
  to the other person and revoked, and must pair again with new keys (§6.2); the relay and devices agree on this,
  because devices also keep the first accepted binding. Recommendation for G1 (not changed here): `PUT
  /v2/devices/{device}` is self-authenticating under the account PK only, with no proof of possession of `dk_sig`; requiring
  one for new registrations would narrow pre-registration of not-yet-registered (v1) device ids.
  Otherwise `restore_invalid`. Entries are sorted and unique by device. For each held revocation of an ever-device,
  require the same or stronger reason: compromised > lost = retired. Missing/weaker coverage returns
  `restore_missing_revocation` with sorted `devices`. Byte identity with the earliest chain evidence
  is an F1 host rule, not a relay rule. Preserve strongest reasons; grow ever_devices atomically.
- **R5 (P3-D13):** applied restore IDs are single-use. Exact publication retries return the stored
  prior result. Rejected IDs are not consumed. A source-bound transition pins both C and T permanently.

Refusal codes are 409 for every evidence failure on both routes, `restore_not_owner` included (genesis and
checkpoint alike, review 8); 401 is reserved for the outer object's `bad_signature`, 400 for shape and size.

A bootstrap null-source restore still runs R0/R1/R4/R5 and proves its exact target from acc_0, including
its restored entry; there is no source comparison or abandoned proof against C. `line.at <= T.o.at` and
the future ceiling remain. Initialized receivers never apply null-source transitions.

**The P3 owner-device policy (P3-D23/D24).** This is deliberately narrower than full F1 replay:
a removed device or demoted delegation owner can pass checkpoint-only verification while still holding
a PK-certified, unrevoked operate device. Full hosts replay owner role, membership, device introduction/
removal and scopes at from_seq. The relay's current-list check catches honest-host mistakes; WSK signs
those lists, so they are not authorization evidence in bundles. No host mandate may sign these restores.
P8's owner-signed roster is required to close this stated gap. Historical devices check certificate expiry
against line.at, not today's clock, plus source/target anchors and in-bundle revocations. A later local
lost/retired revocation does not invalidate history; a later compromised revocation raises an alarm without
changing validity. Durable local revocations and tombstones still prevent resurrection (P3-D24/D25).
**"Later" is the receiver's own order, never `line.at` (review 1):** a revocation counts as later only when the
receiver first learns it after it has judged the transition, from a higher-n bundle in the same walk or after its
commit. Any revocation of the signer it already holds when it judges the transition, from before the sync or from
a lower-n bundle in this walk, refuses that transition (`chain_diverged`), whatever the reason and whatever
`revoked_ms` says. This matches F1's receiver (`judge_offer` refuses a known-revoked signer).

**Where a device's revocations come from, and what each is used for (review N4).** A device holds two sets:
*chain* revocations, learned from accepted restore bundles (with the bundle's `pk_pub`), and *local* revocations,
learned out of band (the §19.5 revocation feed, the member list, the owner's own action). The **signer check**
uses both sets: every revocation the device holds refuses its signer. The **person/key binding** of carried
evidence uses everything the device knows of a device's person: chain revocations, local revocations and known
active devices (the pairing member list, applied signers, accepted evidence; review F2, orch-core #377).
A member added after pairing is bound on first sight: its first accepted evidence or applied signature on the
chain. The device does not take bindings from later member lists, because those are WSK-signed and a WSK holder
could pre-bind persons with them; P8's owner-signed roster closes this. Only the
**completeness check** (a workspace restore must list every held revocation, a `compromised` one as
`compromised`) uses chain revocations alone. Both sets are durable and both feed the resurrection rule. A local
`compromised` revocation of a device that signed an applied transition raises the alarm when it is learned,
independent of any sync (review F6).
Consequences, stated in full: a device that learned an *unrelated* device's revocation out of band is not
stranded behind an older genuine workspace restore that could not list it. A device that learned the *signer's*
revocation out of band (any reason) while behind an older genuine restore by that signer stays refused at that
restore until the owner re-pairs it from a fresh baseline; this is accepted, because refusing is the only rule a
WSK holder holding a revoked device's key cannot exploit. F1's receiver (orch-core #377 `ReceiverView`) takes one
`known_revocations` list for both the signer and the completeness check; the split is a relay-side refinement,
still to be raised with stream A (orch-52) for F1 §5.10. A `compromised` revocation of an accepted restore's signer
that F1 reports as learned later (`Verdict.alarms`) is the alarm the walk raises below, for this walk and later ones.

**Reads, retention and pairing (P3-D13/D19/D20).** A GET returns an immutable endpoint E. Page transitions
with `after_n=k&to=E`, ordered by target_n, exclusively after k and no later than E.n; k does not need to
name a retained checkpoint. Every bundle includes restore_id, log, source_hash, target_hash, target_n,
line, cert and authz. Fetch checkpoint objects by hash and proofs against those same hashes. Superseded
checkpoints live 24 hours from supersession; transition-referenced checkpoints live permanently.
An expired E returns 410 `checkpoint_gone` on every endpoint-bound read; unknown hashes return 404.
Keep the receiver's H unchanged until the entire walk is verified. Restart with a new E after 410;
missing evidence means incomplete sync, never permission to re-pair or discard rollback protection.

**Device synchronisation (normative, review 2).** A checkpoint-only receiver (orch-mobile) holds `H` (its verified
baseline or last commit, or none), its applied restore IDs, its durable revocations and the pairing-pinned owner PK,
WSK and genesis. It MUST run this walk; `ref/checkpoints.py` `sync_walk`/`judge_offer` is the reference, and the
`walk_*` vectors include states a malicious relay would serve. Every step is a refusal on failure, and a refusal
leaves the device exactly as it was.

1. `GET checkpoint` (or `?hash=E` to resume, which MUST return exactly E) gives E. Fetch every checkpoint by hash
   and verify that its `h_checkpoint` equals the requested hash and its WSK signature; the judge then checks the
   §5.10 shape, its workspace, its genesis (else `genesis_mismatch`) and the clock ceiling: an `o.at` more than
   300 s past the device clock is 409 `checkpoint_time` (F1 `checkpoint.future`). `work = H`.
2. Page `GET transitions?after_n=H.n&to=E`. A page with a non-null `next` MUST be nonempty and `next` MUST be
   strictly greater than the previous cursor and at most `E.n`; otherwise `sync_incomplete`.
3. For each bundle B, in order:
   - If `B.source_hash` is non-null and differs from `h_checkpoint(work)`: fetch C by hash; C MUST have
     `n > work.n` (else `chain_diverged`), and `work → C` MUST be an exact extension proved by accumulators for every
     log of C (step 5). Then `work = C`.
   - Fetch T by `B.target_hash`; `T.o.n` MUST equal `B.target_n`.
   - Judge B before fetching its proofs: R0 shape, the person and host signatures in `B.log`'s context, the
     delegation content equal to the pinned card's (`o`), the certificate and delegation under the pinned owner PK
     (actor = delegation owner = certificate person and device, operate, no `drop:` scope, valid at `line.at`), the
     signed `source` MUST equal `{n: work.o.n, hash: h_checkpoint(work)}` (the R2 equivalent; a null `source`
     only when the device has no `work`, so an initialized device refuses every null-source bundle),
     `line.id` not already applied, `work.o.at <= line.at <= T.o.at`, a ticket `ws_seq` at most T's workspace
     height, the signer not revoked inside B, and the revocation rules above (every revocation the device holds,
     chain or local, including those learned from earlier bundles of this walk, refuses its signer; carried
     evidence for any device the device knows, active or revoked, MUST come from its known person and key; a
     workspace restore MUST list every chain revocation, a `compromised` one as `compromised`).
   - Then prove R3 from GET proof pages bound to C and T: from_seq below C's height takes the retained prefix
     from T's branch (from `acc_0`) and the abandoned suffix from `acc_from` to C (exactly `C.seq − from_seq`
     heads, folding to C's acc, `abandoned` covering C); otherwise the forward heads from C's entry. The restored
     entry of T MUST be reached from `{from_seq, head, acc_from}` by a consistent proof (else `sync_incomplete`)
     whose first head is `event_head(line)`; a consistent proof whose first head is another event means T is
     signed over another head and is `chain_diverged` (orch-core #377; `sync_incomplete` is only for missing
     or malformed proofs).
     Every other log of T MUST extend work exactly. A workspace log with from_seq 1 starts at the pinned genesis.
   - Record `line.id`, add B's revocations (strongest reason wins), `work = T`.
4. Finally judge E against work: equal n requires the identical object; a lower n is `ignored` only if no
   transition was walked and no entry of E is higher or conflicting (a lagging relay: keep H, never downgrade);
   a higher n MUST have `o.at >= work.o.at`, keep every log, and extend work exactly.
5. Proof pages are paged with `next` and MUST NOT return more heads than the signed heights allow (`to` height
   minus `from` height), nor more heads per walk than the device's own ceiling (the reference uses 2^22), since
   WSK-signed heights alone bound nothing; an empty page with a non-null `next`, a fold that misses the signed acc,
   a signed entry whose head or seq disagrees with its proof, or a 404 is `sync_incomplete`. A device without H
   requires full proofs from `acc_0`, with the workspace log's first head equal to the pinned genesis.
6. Commit atomically: `H = E` (or unchanged on `ignored`), the applied IDs with each transition's signer device,
   and the revocations. Whenever the device holds a `compromised` revocation (chain or local) of a device that
   signed any applied transition, in this walk or an earlier one, it raises an alarm and history stays valid; the
   alarm does not depend on how the history was split into walks (review N3). On 410 `checkpoint_gone` keep H and
   restart with a new E.

The authenticated pairing `approved` answer carries the host's exact `{n, hash}` baseline, or null only
when none exists. POST baselines pins it for seven days (16 per workspace); retries do not extend expiry.
DELETE releases it early, idempotently: W(g) releases any pin, an initialized D(m) member only the pin whose
`offer_id` it names (any other member request is a no-op). The principal's role is always explicit; the
reference refuses a delete that names none (fail closed). A device must fetch and verify
that baseline before initialization; it never downgrades it and relay emptiness cannot override a non-null
baseline. After 24 hours without retrieval it asks the host for a current reference under the same rule.

**Host publication (P3-D21).** Under the append lock, persist the exact C/T, full signed restore,
certificate, delegation and durable branch proofs in the outbox alongside the append. After releasing the
lock, publish in order with backoff; delete only after 200. The restore follows its named source and later
checkpoints wait behind it. Decision/person-event admission tombstones survive restores. No network call
holds the store lock. The owner's client independently compares the proposed source with the relay;
flushing the outbox is not a prerequisite to signing.

**Transport details requiring design sign-off (G0b, P3-D13/D19/D20).** The source design leaves the following
encodings unspecified. The reference and fixtures use explicit candidate conventions; these are not F1
rules and must be confirmed before G4 ships:

1. Page digest: `sha256:` + SHA-256 of `cj(page without digest)`, without a new domain label.
2. Null path source: literal `null`. The final restore names its `log` explicitly (amended in G0b after the
   security review: searching T's entries cost one 512 KiB canonicalisation and P-256 verify per ticket).
3. `transitions_head` is the greatest target_n at/below the requested checkpoint, or zero. Transition
   next is the last target_n (returned to after_n); proof next is the folded acc (returned to from),
   retaining the same to hash. This is the stated exception to §19.6's opaque `next`.
4. Baseline identity is hash, matching DELETE's path. The design does not define multiple offers pinning
   the same hash; this reference returns the existing pin without extending it.
5. The design's §6.2 example uses `after=<held hash>`; §3.4/§6.4 and this contract use `after_n`.
   F1 permits heads after the restore in T; P3 R3 intentionally requires T's entry to end at the restore.
   P3 requires full first-publication proof for durable nodes, whereas F1 judge_offer accepts a verified
   initial checkpoint without ancestry. These are relay restrictions, not changes to F1's event shape.
6. **G4 preconditions (review 4 and 7), not G0b contract changes.** (a) `GET proof` walks `prev_acc` from E back to
   `from` on every page, O(history) per page and O(N²/limit) per full sync; G4 MUST index nodes per branch (for
   example skip pointers or a memoised ordered acc list per `(E, log)`) so a page costs O(limit), or charge walk
   steps to the §19.6 budgets and state the bound. The reference device walk also reads a restored log from
   `acc_0` to find `acc_from`. (b) The HTTP fixtures do not yet pin cross-workspace isolation: G4 MUST add a second
   workspace's token and fixtures for B's sessions on A's routes (403 `not_eligible`), A's checkpoint, proof,
   staging and baseline hashes requested under B (404, or a no-op for DELETE), and bind the transitions 404,
   baseline 404/410, staging 429 and checkpoint `too_large`/`wrong_suite` refusals to vector steps.
