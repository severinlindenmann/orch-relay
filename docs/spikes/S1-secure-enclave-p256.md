# S1: Secure Enclave P-256 interop (protocol v2 suite 2)

Issue: severinlindenmann/orch-relay#3. The issue text predates D46 (it talks about WebCrypto and Ed25519); this
spike answers the current question: do Apple Secure Enclave and CryptoKit P-256 keys interoperate with protocol v2
suite 2 and with Python `cryptography` (D45 native Swift app, iOS 18+; D46 one crypto suite, P-256)?

## Decision

**Yes on the macOS Secure Enclave; iPhone pending (TestFlight). The iOS Simulator emulates the Secure Enclave
(`SecureEnclave.isAvailable == true` there is not hardware evidence).** Suite 2 works as specified with the Secure
Enclave on an Apple-silicon Mac, with no change to the wire format: a Secure Enclave signing key gives a 65-byte
uncompressed public key and a 64-byte raw `r||s` signature that the reference (`ref/orch_protocol_ref.py`,
`SuiteP`) and Python `cryptography` verify; a Secure Enclave key-agreement key produces the same 32-byte
x-coordinate shared secret as Python, and seals made with it open in Python. The P-256 maths cannot differ on an
iPhone, but custody behaviour (accessibility classes, user presence, reinstall, passcode change) is untested
there. The custody half of this document (keys, keychain, presence) therefore carries open questions: see
"Open questions for the owner" and "Protocol caveats".

## Results

| Platform | What ran | Result |
|---|---|---|
| macOS 27.0, Apple silicon, **Secure Enclave** | `swift test` (7 SE tests) + `s1-fixtures` fixture verified by Python (37 pytest tests incl. negative cases) | pass |
| macOS 27.0, CryptoKit **software** P-256 | `swift test` (14 tests: keys, signatures, malformed signatures and public keys, ECDH, HKDF, seal, salted AEAD, off-curve, high-s twin) | pass |
| iOS 18.3.1 Simulator, software P-256 | `xcodebuild test`, 14 software tests | pass |
| iOS 18.3.1 Simulator, `SecureEnclave` API | same run, 7 SE tests | pass, **but not device evidence**: `SecureEnclave.isAvailable == true` in the Simulator (see below) |
| Real iPhone, Secure Enclave | needs TestFlight build | **pending** |

The Simulator finding is the opposite of what one would expect: on this Apple-silicon host with the iOS 18.3
runtime, `SecureEnclave.isAvailable` reports **true** and SE key creation, signing, ECDH and `dataRepresentation`
reload all work. The Simulator emulates the API on the host, so it does not show what an iPhone's Secure Enclave
does (accessibility classes, `.userPresence`, key attestation, key lifetime across reinstall). App code must not
treat `isAvailable == true` as proof of hardware. The tests print `S1-ENV isAvailable=...` so each run records it.
One SE test (`testDataRepresentationReload`) took 21 s on its first run in the Simulator (warm-up); later runs are
well under a second.

## API names and formats (what the app uses)

| Item | API | Format | Suite 2 field |
|---|---|---|---|
| Public key, both key kinds | `.publicKey.x963Representation` | 65 bytes `04 || x || y` | `dk_sig_pub`, `dk_kx_pub` (spec: 65-byte uncompressed point) |
| Import a peer public key | `P256.Signing.PublicKey(x963Representation:)` / `P256.KeyAgreement.PublicKey(x963Representation:)` | throws on off-curve, wrong length, compressed | on-curve check is done by CryptoKit |
| Signing key (device) | `SecureEnclave.P256.Signing.PrivateKey(accessControl:)` | opaque handle | `dk_sig` |
| Key-agreement key (device) | `SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl:)` | opaque handle | `dk_kx` |
| Signature | `key.signature(for: Data)` (hashes with SHA-256 itself) | `ECDSASignature.rawRepresentation` = 64 bytes `r||s`, big-endian | the protocol signature, as is |
| Signature, DER (Security/OpenSSL interop only) | `ECDSASignature.derRepresentation` | ASN.1 `SEQUENCE{r,s}` | not on the wire; Python converts with `decode_dss_signature` |
| Verify | `PublicKey.isValidSignature(_:for:)` | takes the message, not a digest, with `for: Data` | |
| ECDH | `sharedSecretFromKeyAgreement(with:)` then `sharedSecret.withUnsafeBytes { Data($0) }` | 32 bytes: the **x-coordinate**, not hashed | equals `cryptography` `ECDH().exchange` and the vector `shared_secret` |
| HKDF | `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` | empty salt is HashLen zero bytes (identical to RFC 5869, to `ref.hkdf`, to WebCrypto) | `info` is `label|field|field` ASCII |
| Seal AEAD | `AES.GCM.seal(_:using:nonce:authenticating:)` with a 12-byte zero nonce; wire = `ciphertext || tag` (do not use `combined`, it prepends the nonce) | | `eph_pub (65) || ct || tag (16)` |

Do not use `SharedSecret.hkdfDerivedSymmetricKey` for the protocol KDF: it is the right primitive, but `ref` builds
`salt = eph_pub || rcpt_pub` and `info = ctx(label, purpose, rcpt_id)`, which is simplest to keep explicit. The
spike's `S1Support` (`hkdf`, `ctx`, `sealKey`, `sealAAD`, `sealTo`, `openSealed`; `sealTo` takes no ephemeral key, the deterministic seam is `_sealToWithEphemeralForVectors`, test-only) reproduces every suite 2 `hkdf`,
`seal`, `seal_open` and `salted_aead` vector byte for byte, and `openSealed` works the same for a software key and a
Secure Enclave key through one protocol (`KeyAgreementKey`).

### Persistence and keychain

- `dataRepresentation` of an SE key is a 284-byte opaque blob (sig and kx alike) wrapped to this device's Secure
  Enclave. `SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:)` reloads it and gives the same public key and
  working signatures. The software `P256.*PrivateKey` initialisers refuse it (they throw on its length; this shows
  the type boundary, not that the blob hides the scalar. Non-exportability is the API surface: `SecureEnclave.P256.*`
  has no raw, x963, PEM or DER export).
- **The blob is wrapped to the device, not to the app.** On the same Mac, a second, unrelated unsigned executable
  loaded a blob written by the first and signed with it without any prompt (security review probe; key created with
  `.privateKeyUsage` only). Any process on the device that can read the blob can use the key, limited only by the
  key's own access-control flags. So **the keychain item that holds the blob is the custody boundary**, not the blob:
  store it only in the data-protection keychain (on macOS `kSecUseDataProtectionKeychain = true`), with the app's
  access group (shared with the extensions that need it), a `ThisDeviceOnly` accessibility class, never
  `kSecAttrSynchronizable`, never in a file or `UserDefaults`; and put user presence on keys whose use must be a
  human act. Re-check on an iPhone, where the sandbox and access groups apply.
- **Keychain write, what was and was not shown.** `swift run s1-fixtures --probe-keychain` (committed) adds the blob as a
  `kSecClassGenericPassword` item: the **legacy file keychain** accepts it from an unsigned binary
  (`SecItemAdd = 0`), but the **data-protection keychain, the production path, fails with `-34018`** (missing
  entitlement). So the data-protection keychain write is **pending** for a signed app; nothing here shows it works.
- Keep the 65-byte public key next to the item so the app can display the device identity without touching the SE.
- **Private keys are not exportable.** A lost phone's `dk_kx` cannot be backed up. Everything sealed to it (WK/SK
  grants) must be re-granted by another device, which the design already does (wk_grants). See "Open questions" for
  `PK`, which is different.
- Software `P256.*PrivateKey` is exportable (`rawRepresentation`, 32 bytes). Use it only for tests, never for the
  production device key.

### Access control and user presence

Created with `SecAccessControlCreateWithFlags(nil, <accessible>, <flags>, &err)`. `.privateKeyUsage` is mandatory for
SE keys.

| Use | Flags | Behaviour |
|---|---|---|
| Automatable (tests, `s1-fixtures`) | `.privateKeyUsage` | key usable without any prompt |
| Per-use presence | `[.privateKeyUsage, .userPresence]` | Touch ID / Face ID, falls back to device passcode, on every signature or agreement |
| Biometry only | `[.privateKeyUsage, .biometryCurrentSet]` (or `.biometryAny`) | `CurrentSet`: key invalidated when the enrolled biometrics change (re-enrol the device) |

Pass a pre-evaluated `LAContext` as `authenticationContext:` to reuse one authentication for several operations
(`touchIDAuthenticationAllowableReuseDuration`, at most 5 minutes). `swift run s1-fixtures --presence` (in `spikes/s1/tool`)
creates a `.userPresence` key and signs once. **It prompts and blocks on a human; no test uses it and the automation did
not run it.**

**Accessibility class.** The earlier `-25308` / `AKSError=-536870174` (`kIOReturnNotPermitted`) on
`WhenUnlockedThisDeviceOnly` and `WhenPasscodeSetThisDeviceOnly` was caused by a **locked screen** in the test host:
with the screen unlocked, both create keys fine from an unsigned binary (reproduced independently by the security
reviewer and again here). The tests now use `WhenUnlockedThisDeviceOnly` and turn `-25308` into a skip with the
message "device/screen is locked".
`AfterFirstUnlockThisDeviceOnly` is a **downgrade for a signing key**: after the first unlock since boot the key can
sign while the device is locked. It is for headless CI and for keys that must work in the background; do not copy it
for `dk_sig`.

Per-key guidance (recommendations for the crypto group; the owner decides):

| Key | Class | Flags | Why |
|---|---|---|---|
| `dk_sig` | `WhenPasscodeSetThisDeviceOnly` (or `WhenUnlockedThisDeviceOnly`) | `.privateKeyUsage` + `.userPresence` per D46, or `.biometryAny` / `.biometryCurrentSet` if "Face ID / Touch ID only, no passcode" is meant | must not sign while locked; presence for human approvals. Resolve open question (a) first |
| `dk_kx` | `AfterFirstUnlockThisDeviceOnly` | `.privateKeyUsage` only | grants and push keys must be opened in the background and in the notification service extension while the phone is locked. Unsealed `WK_e` / `K_push` kept for the extension get the same class, nothing broader |

## ECDSA behaviour

- **Non-deterministic.** CryptoKit (software and SE) randomises k: two signatures over the same message differ
  (tested for both). Vectors therefore check *verification* (`sign` cases), never exact signature bytes. The
  reference signs with RFC 6979 only so the vector file is reproducible; the spec already says real signers may
  randomise.
- **No low-s normalisation.** Roughly half of Secure Enclave signatures are "high-s" (`s > (n-1)/2`). Observation,
  reproduce with `cd spikes/s1/tool && swift run s1-fixtures --stats 400`: 177/400 (44%) in one run, 193/400 and
  112/200 in earlier ad-hoc runs; all consistent with 50%. Verifiers MUST NOT reject high-s. This matches the spec
  (`high_s_twin_verifies` is `valid: true`).
- **Malleability.** CryptoKit and `cryptography` both accept the twin `(r, n-s)`; the SE and software fixtures are
  checked for this in Python (`test_signature_s_malleability`) and Swift checks the vector twin
  (`testHighSTwinIsAcceptedByCryptoKit`). Hence the existing rule: a signature is never an identifier, dedupe key or
  replay token.
- **Vector `sign` section:** CryptoKit agrees with every case including the rejections (other key, changed
  message, 126-byte signature, `r = 0`, `s = n`, off-curve key). Beyond the vectors, `testMalformedSignaturesRejected`
  and the Python `test_malformed_signature_rejected_by_ref_and_cryptography` check `s = 0`, `r = 0`, `r = n`, `s = n`,
  `r`/`s` = 2^256-1, 63, 65 and 0 byte signatures on both sides. CryptoKit *parses* out-of-range `r`/`s`
  (`ECDSASignature(rawRepresentation:)` succeeds for `s = 0`, `r = n`, ...) and only `isValidSignature` returns false;
  63/65-byte signatures throw. So the app applies the spec's explicit length and range check first
  (`S1Support.strictVerify`). Public keys: CryptoKit rejects compressed 02/03, hybrid 06/07, identity `04||0^64`, a
  single `00`, wrong lengths and off-curve points (`testNonUncompressedPublicKeyEncodingsRejected`); `ref`'s
  `sig_pub_ok` rejects the same list.
- **DER vs raw.** CryptoKit's `rawRepresentation` is already the protocol's 64-byte `r||s`. DER is only needed for
  Security-framework calls (`SecKeyCreateSignature` returns DER) and for OpenSSL/`cryptography`'s `verify`; the Python
  tests convert both ways and compare.
- Throughput (same `--stats` run, observation only): about 5.6 ms per SE signature on this Mac.

## Interop evidence

Swift to Python (committed fixture `spikes/s1/fixtures/se-mac.json`, verified by `tests/spikes/test_s1_vectors.py`):

- SE signing key, 3 messages: raw and DER both verify through `ref` `SuiteP.verify` and `cryptography`; DER and raw
  encode the same `(r, s)`; the high-s twin verifies.
- SE key-agreement key against vector key `laptop.kx`: the SE-computed shared secret equals what Python computes
  from the SE public key and the vector private key.
- Seal with an SE key standing in as the sender's ephemeral key (**test-only**: in production the ephemeral key is
  always a fresh software key generated inside `sealTo`, never an SE or other long-lived key, because the zero nonce is
  safe only when K is unique per seal; the fixture uses the SE key once, only to push an SE ECDH output through
  Python's `open_sealed`), recipient the vector key `phone.kx`: `ref.open_sealed` opens it (so ECDH, `salt = eph_pub || rcpt_pub`, the `kdf_seal` info and the AAD all agree), and a tampered blob fails.
- Same for a software CryptoKit signer and sealer.

Python to Swift (vectors): all software vector checks above, and in `swift test` the SE recipient path
(`testSealToAndFromSecureEnclave`) round-trips a software-sealed message through an SE key-agreement key and the
reverse. A seal produced in Python *to an SE public key* is not committed, because an SE key cannot be recreated
across runs; the equal shared secret plus the identical sealing code path is the evidence.

## Protocol caveats and findings for the contract

Findings (the spike changes neither spec nor protocol):

1. **Vector `seed` is not the private scalar.** `ref` derives `d = int(seed) mod (n-1) + 1` (`SuiteP._priv`), so
   importing the 32 bytes straight into CryptoKit gives a different key. `S1Support.scalar(fromSeed:)` does the mapping.
   The mapping is slightly biased (about 2^-32) and is for fixed test seeds only; it is not a key-generation method.
   A deterministic derivation of a real key (see open question (b)) needs FIPS 186-5 A.2.1 (at least 320 bits of HKDF
   output, then `mod (n-1) + 1`) or rejection sampling, with its own label.
2. **Suite 2 is described as the "fallback" (D22, `docs/protocol-v2.md` §1 table and around line 1716) while D46 makes
   it the only suite.** Wording only. Suite 1 (Ed25519/X25519) is impossible in the Secure Enclave, which supports
   P-256 only.
3. **Signing and key agreement are separate SE key types** in CryptoKit (`SecureEnclave.P256.Signing` vs `.KeyAgreement`).
   The protocol already has separate `dk_sig_pub` and `dk_kx_pub`, so nothing changes. Do not plan on one key for both.
4. **Verifiers must accept high-s and must range-check** (`1 <= r,s <= n-1`, length 64, 65-byte `04` key) themselves
   before calling CryptoKit; CryptoKit parses out-of-range `r`/`s`. No v2 construction uses signature bytes as an id,
   dedupe key, replay key or chain link (checked by the security review); keep it that way, e.g. if a "device-signed
   ledger entry" (§13) ever gets an id, it must not be a hash over bytes that include the signature.
5. **Sealing needs a fresh software ephemeral key per seal** (§5.3). The zero nonce is safe only because K is unique
   per seal; a long-lived key (including an SE key) as `eph` would reuse key and nonce (plaintext XOR leaks, GHASH key
   recoverable). `sealTo` therefore generates it internally.
6. **All-zero shared secret.** §5.3 says "(all-zero is an error)" generically; `ref` `SuiteP.kx` does not check it. A
   point with `x = 0` exists on P-256, but nobody without the recipient's private key can force `d*Q` onto it, so it
   is not exploitable. Either add the check for uniformity or scope the sentence to suite 1.
7. **Vector gaps for suite 2** (contract, not this PR): `sign` has `r_zero` and `s_equals_n` but no `s_zero`,
   `r_equals_n`, `r`/`s` above n, 63/65-byte signatures, identity, compressed or hybrid public keys; `seal_open` has no
   off-curve, identity or compressed `eph_pub` case. This spike tests them locally (see ECDSA behaviour); adding them to
   the vector file pins the explicit checks on both sides.
8. **`SecureEnclave.isAvailable` is true in the Simulator**; do not use it as a hardware signal. Gate on build target
   and, on iOS, App Attest if the relay needs device-class assurance.
9. **Limits of this evidence:** no real-iPhone data; the fixture's `secure_enclave_available` is self-reported and
   Python cannot tell an SE signature from a software one; the Swift tests are not in CI (only the Python fixture check
   runs everywhere).

### Proposals for `docs/protocol-v2.md` (wording only, for the owner to accept or reject)

- **§1.1 table header and line 94:** "Suite 2 `p256` (the only suite, spec D46)". "Primitives come only from Apple
  CryptoKit, WebCrypto and the Python `cryptography` package." Retire "fallback" here and in §18 R5.
- **§1.1 line 108:** "Both private halves are non-extractable: in the Secure Enclave on iPhone and Apple-silicon Macs
  (D46), and as non-extractable WebCrypto keys in a browser. `PK` is not a device key; its custody and recovery are
  defined with the recovery kit (§6.5)."
- **§1.2 suite 2:** "A signature MUST be 64 bytes, with `r` and `s` in `1 ... n-1`, checked by the verifier itself before
  calling the library. Verifiers MUST accept both low-s and high-s signatures (Secure Enclave signers do not normalise).
  ECDSA is malleable, so no signature, and no hash over bytes that include a signature, is ever used as an identifier,
  dedupe key, replay key or chain link, in either suite."
- **§16 vectors:** "For suite 2, a key `seed` is not the private scalar: `d = int(seed) mod (n-1) + 1`
  (`SuiteP._priv`). This mapping exists only to make the vectors reproducible and MUST NOT be used to generate real keys."
- **§5.3:** change "(all-zero is an error)" to "(suite 1: an all-zero X25519 output is an error)", or keep it and add the
  check to suite 2 implementations.
- **§5.3:** add "An ephemeral key is generated in software for each seal and discarded. A long-lived key (including a
  Secure Enclave key) MUST NOT be used as `eph`."
- **If open question (a) is resolved by a key split:** "Each device holds `dk_sig` (presence-gated; `sig_decision`,
  `sig_ws_cosign`, `sig_webauthn_bind`) and `dk_auth` (unattended; `sig_bridge` requests and `sig_relay_auth`), both
  listed in the certificate. `device_id` stays derived from `dk_sig_pub`."

## Open questions for the owner

Stated neutrally; the spike decides neither.

**(a) User presence on `dk_sig` versus unattended signatures (D41 / D46).** D46 says device keys sign only after Face ID or
Touch ID. In protocol v2 the one `dk_sig` signs human approvals (`sig_decision`, `sig_ws_cosign`, `sig_webauthn_bind`) and
also unattended traffic (`sig_bridge` on every request, `sig_relay_auth` on every relay login; §3 table). With
`.userPresence` on `dk_sig`, every bridge request and relay login would prompt; without it, D46 / D41 do not hold.
Options from the security review:
1. One presence-gated `dk_sig` plus an `LAContext` reuse window (`touchIDAuthenticationAllowableReuseDuration`, maximum
   5 minutes). Presence then covers a window, not one approval.
2. A protocol amendment splitting an unattended transport/login key (`dk_auth`) from the presence-gated approval key
   (`dk_sig`); wording above.

The manual `--presence` mode has not been run; it should be run once by a human and the prompt recorded.

**(b) Where `PK` (the person key) lives, given the 24-word recovery code.** `PK` is made by the primary device and signs
certificates, revocations, delegations and cert challenges (`docs/protocol-v2.md` around line 361). It cannot live
only in the Secure Enclave if the recovery code must restore it: SE keys can neither be imported nor exported. If `PK`
is lost with the primary phone, nobody can sign the revocation of that lost phone, and re-creating `PK` changes
`person_id` and every `pk_pin`. Options from the review:
1. `PK` is a software P-256 key that is recoverable from the recovery code (deterministically derived from the recovery
   secret with a proper hash-to-scalar, see finding 1, or stored encrypted under it), held at rest wrapped by an SE key
   on the primary device.
2. `PK` in the Secure Enclave, with no recovery from the 24 words (recovery then means a new `PK`, a new `person_id`
   and re-pinning).

WSK / WXK are host keys, outside this spike.

## How to reproduce

```
# T0 (each < 30 s)
cd spikes/s1 && swift test --filter SoftwareP256Tests
cd spikes/s1 && swift test --filter SecureEnclaveTests
uv run pytest tests/spikes/test_s1_vectors.py -x -q

# T1
cd spikes/s1 && swift test                                   # macOS, 22 tests
xcrun simctl create "S1 iPhone 16" com.apple.CoreSimulator.SimDeviceType.iPhone-16 \
  com.apple.CoreSimulator.SimRuntime.iOS-18-3                # once; no iPhone existed on this machine
cd spikes/s1 && xcodebuild test -scheme S1 \
  -destination 'platform=iOS Simulator,OS=18.3.1,name=S1 iPhone 16'
uv run pytest -q

# regenerate the fixture (needs a Secure Enclave Mac); ECDSA is random, so the file changes every time
cd spikes/s1/tool && swift run s1-fixtures                   # always changes se-mac.json (random ECDSA): commit only if intended
cd spikes/s1/tool && swift run s1-fixtures --stats 400       # high-s ratio and ms per signature (observation)
cd spikes/s1/tool && swift run s1-fixtures --probe-keychain  # legacy vs data-protection keychain status codes
cd spikes/s1/tool && swift run s1-fixtures --presence        # MANUAL: prompts for Touch ID / passcode
```

- Vector file location: env `S1_VECTORS`, else `tests/vectors_v2.json` resolved from the source file path (works in
  `swift test` and in the Simulator, which runs on the host filesystem). The env var does not reach the Simulator test
  process; there it must be passed as `SIMCTL_CHILD_S1_VECTORS=... xcodebuild test ...`.
- Regenerating `fixtures/se-mac.json` always produces a diff (randomised ECDSA, new SE keys); only commit it on purpose.
- The Simulator runtime's OS string is `18.3.1`, so `OS=18.3` does not match; use `OS=18.3.1` (or omit `OS=`).
- The fixture generator is a sibling package (`spikes/s1/tool`) because an executable target in the main package
  leaves the `S1` scheme without any iOS destination (`Supported platforms for the buildables in the current
  scheme is empty`), which breaks `xcodebuild test` for the Simulator.
- Package uses Swift language mode 5 to keep top-level code in the tool simple; CryptoKit only, no third-party
  dependencies.

## Pending

- Real iPhone Secure Enclave run (TestFlight build, Apple account): confirm the table row, the accessibility class
  behaviour (`WhenUnlocked*`), `.userPresence` / Face ID prompts, `dataRepresentation` after an app reinstall and
  after a passcode change, and that `isAvailable` semantics on device match the expectation.
- Run the manual `--presence` mode once by hand on this Mac and record the prompt.
- Data-protection keychain write/read of the SE blob from a signed app (`-34018` from the unsigned tool), and blob use from
  a second app or extension on an iPhone.
