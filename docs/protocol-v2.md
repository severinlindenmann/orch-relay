# orch protocol, version 2

This document is the wire contract of orch v2. It fixes the exact bytes that the three implementations
exchange, and what each of them does with an input that is not right:

- **orch-core**: the workspace host (`orch serve` / `orch host`);
- **orch-relay**: directory, relay (bridge v2), drop and push;
- **orch mobile**: the PWA, and every other browser device.

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
- **Suites.** Ed25519 + X25519 by default. P-256 is a separate suite id, used per deployment and never
  negotiated (§1).
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

| | Suite 1 `ed25519-x25519` (primary, spec D22) | Suite 2 `p256` (fallback) |
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
| `sig_checkpoint` | `orch/v2/sig/checkpoint\|` | signature | `WSK` | a checkpoint (F1 §5.10) |
| `h_device_id` | `orch/v2/id/device\|` | hash | | device id |
| `h_person_id` | `orch/v2/id/person\|` | hash | | person id |
| `h_pin_person` | `orch/v2/pin/person\|` | hash | | `pk_pin` |
| `h_pin_workspace` | `orch/v2/pin/workspace\|` | hash | | `wsk_pin` |
| `h_sas` | `orch/v2/sas\|` | hash | | the 6-character pairing code |
| `h_sas_cert` | `orch/v2/sas-cert\|` | hash | | the 6-character code of the primary's challenge |
| `h_dek_commit` | `orch/v2/dek-commit\|` | hash | | key commitment for a DEK |
| `h_card_key_commit` | `orch/v2/card-key-commit\|` | hash | | key commitment for a card key `CK` |
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

It then records the device as revoked and removes it from its member list. If the device was a member, it
**rotates** before it seals anything new.

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
- `card_seq` strictly increases (`stale_card`).
- `wxk_version` stays the same with the same key, or rises by exactly 1 with a different key
  (`wxk_changed_without_version`, `bad_wxk_version`).

**DECIDED HERE:** the delegation and its labels; `sealed_hash`; `ck_commit`; `card_seq`; the URL form; and
the update rules. Vectors: `card.cases` (16, including a rotation signed by `WSK` alone, a delegation
signed by another person, a delegation for another `WSK`, and a changed delegation), and the round trip
`test_round_trip_card`.

### 7.2 Member list and epochs

A signed object, signed by `WSK` with `sig_member_list`:

```
{"v":2, "suite", "kind":"member_list", "workspace_id", "epoch", "list_seq", "issued_ms",
 "members": [{"device_id": hex, "scopes": [...]}, ...]}          sorted by device_id, no duplicates
```

`list_seq` counts every list, and `epoch` counts keys. Adding a device does not change the epoch; removing
one does. **DECIDED HERE:** a separate `list_seq`, because the spec's `{epoch, members}` alone cannot
order two lists of one epoch.

**What the relay checks before it accepts a list:**

1. the signature with the card's `wsk_pub`;
2. the shape: field set, sorted unique hex ids, `epoch ≥ 1`;
3. `workspace_id` is the card's, **including on the first list** (`other_workspace`);
4. the first list has `epoch = 1` and `list_seq = 1`;
5. `list_seq` strictly increases (`stale_list`);
6. `epoch` is the previous one or the previous one + 1 (`bad_epoch`; epochs never skip);
7. if any previous member is missing, `epoch` MUST be the previous one + 1 (`rotation_required`);
8. for every member:
   - not revoked (`revoked`);
   - a valid certificate of the **card owner** (`other_person`; spec D1 C is out of scope);
   - not a scoped agent, and `scopes` a prefix no longer than its `scopes_max` (`scope_exceeded`);
9. a WK grant exists for **every** member at this list's epoch (`missing_grant`).

This is the spec's order: seal, upload, then publish.

On acceptance, the relay deletes the mailboxes, grants and push subscriptions of the devices that left.
Vectors: `member_lists`.

**Host rules (spec §5.4).**

- **When it rotates.** The host rotates at startup and once a day:
  - if the epoch is 90 days old;
  - on a revocation it learns of;
  - on a removal;
  - on `orch keys rotate`.
- **How it rotates:**
  1. generate `WK_{e+1}`;
  2. upload a grant for every remaining device;
  3. publish the list;
  4. seal everything new under `e+1`.
- **What it keeps.** It keeps every old `WK` to read old content. It never seals new content under an old
  epoch (§8.5).
- **New devices (spec D26).** A device that joins at epoch `e` is granted `WK_e` and later epochs only.

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
   https://<relay>/app/pair#v2.<workspace_id hex>.<offer_id hex>.<b64u S>.<b64u wsk_pin>.<b64u pk_pin>
   ```

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
   4. registers the platform passkey exactly as in v1 §9.2, with the v2 challenge (§8.7).

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

### 8.5 Epochs on the bridge

- A request MUST use the host's current epoch.
  - A request at a **lower** epoch whose key the host still holds: after its signature verifies, it is
    recorded and refused `stale_epoch` with `"epoch": current`. The refusal is sealed under the
    request's own (old) epoch, so the device can read it. It contains nothing else.
  - A request at a **higher** epoch, or at an epoch whose key the host deleted, is dropped: there is no key
    to open it with.
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
5. **Replay.** A known rid gets v1 §5.3's answer; a re-sent stored `stale_epoch` carries the current
   epoch.

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

### 8.9 What the relay checks on the bridge

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
| 400 | `malformed`, `wrong_suite`, `cert_invalid`, `cert_expired`, `delegation_mismatch` |
| 401 | `bad_signature`, `stale_timestamp` (`server_ms`), `unknown_workspace`, `replay`, `unknown_challenge`, `expired` |
| 403 | `revoked`, `other_person`, `scope_exceeded`, `not_eligible`, `not_for_this_device` |
| 409 | `other_workspace`, `wsk_changed`, `delegation_changed`, `stale_card`, `wxk_changed_without_version`, `bad_wxk_version`, `stale_list`, `bad_epoch`, `rotation_required`, `missing_grant`, `already_claimed` (`claimed_by`), `version_conflict` (`current`) |
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
| `wk_grants`, `member_lists` | grants; 14 member-list cases (§7.2) |
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
18. `list_seq` beside `epoch`; epochs never skip; the relay requires grants before the list, and checks the
    first list's workspace against the card (§7.2).
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
