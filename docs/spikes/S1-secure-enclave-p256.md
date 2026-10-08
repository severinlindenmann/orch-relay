# S1: Secure Enclave P-256 interop (protocol v2 suite 2)

Issue: severinlindenmann/orch-relay#3. The issue text predates D46 (it talks about WebCrypto and Ed25519); this
spike answers the current question: do Apple Secure Enclave and CryptoKit P-256 keys interoperate with protocol v2
suite 2 and with Python `cryptography` (D45 native Swift app, iOS 18+; D46 one crypto suite, P-256)?

## Decision

**Yes. Suite 2 works as specified with the Secure Enclave, with no change to the wire format.** A Secure Enclave
signing key gives a 65-byte uncompressed public key and a 64-byte raw `r||s` signature that the reference
(`ref/orch_protocol_ref.py`, `SuiteP`) and Python `cryptography` verify. A Secure Enclave key-agreement key
produces the same 32-byte x-coordinate shared secret as Python, and seals made with it open in Python. Caveats
are listed under "Protocol caveats" and "Findings for the contract". Real-iPhone Secure Enclave runs are pending
(TestFlight build, Apple account).

## Results

| Platform | What ran | Result |
|---|---|---|
| macOS 27.0, Apple silicon, **Secure Enclave** | `swift test` (7 SE tests) + `s1-fixtures` fixture verified by Python (19 pytest tests) | pass |
| macOS 27.0, CryptoKit **software** P-256 | `swift test` (12 tests: keys, signatures, ECDH, HKDF, seal, salted AEAD, off-curve, high-s twin) | pass |
| iOS 18.3.1 Simulator, software P-256 | `xcodebuild test`, 12 software tests | pass |
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
spike's `S1Support` (`hkdf`, `ctx`, `sealKey`, `sealAAD`, `sealTo`, `openSealed`) reproduces every suite 2 `hkdf`,
`seal`, `seal_open` and `salted_aead` vector byte for byte, and `sealTo` works the same for a software key and a
Secure Enclave key through one protocol (`KeyAgreementKey`).

### Persistence and keychain

- `dataRepresentation` of an SE key is a 284-byte opaque blob wrapped to this device's Secure Enclave (sig and kx
  alike). `SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:)` reloads it and gives the same public key and
  working signatures; the blob is useless on another device and cannot be loaded into a software key (tested:
  `P256.Signing.PrivateKey(rawRepresentation:)` and `(x963Representation:)` both throw).
- Store the blob as a keychain `kSecClassGenericPassword` item (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
  or `WhenUnlockedThisDeviceOnly`, never a synchronising class, no `kSecAttrSynchronizable`). `SecItemAdd` and
  `SecItemDelete` worked from an unsigned command-line binary on the Mac (status 0). In the real app also keep the
  public key (65 bytes) next to it so the app does not have to touch the SE to display the device identity.
- **Private keys are not exportable.** There is no raw, x963, PEM or DER export on `SecureEnclave.P256.*`; that
  is the point. Consequence for the protocol: a lost phone's `dk_kx` cannot be backed up. Everything sealed to it
  (WK/SK grants) must be re-granted by another device, which the design already does (wk_grants).
- Software `P256.*PrivateKey` is exportable (`rawRepresentation`, 32 bytes). Use software only for tests and as the
  non-SE fallback, never for the production device key.

### Access control and user presence

Created with `SecAccessControlCreateWithFlags(nil, <accessible>, <flags>, &err)`:

| Use | Flags | Behaviour |
|---|---|---|
| Automatable (used by all tests and `s1-fixtures`) | `.privateKeyUsage` | key usable without any prompt |
| Per-use presence | `[.privateKeyUsage, .userPresence]` | Touch ID / Face ID, falls back to device passcode, on every signature or agreement |
| Biometry only | `[.privateKeyUsage, .biometryCurrentSet]` | key is invalidated if the enrolled biometrics change |

`.privateKeyUsage` is mandatory for SE keys. Pass a pre-evaluated `LAContext` as `authenticationContext:` to reuse
one authentication for several operations. The manual mode `cd spikes/s1/tool && swift run s1-fixtures --presence`
creates a `.userPresence` key and signs once; **it prompts and blocks on a human, so no test uses it and it was not
run by the automation**. Which flags the product wants for approvals (D-level decision) is outside this spike.

On this Mac, from an unsigned `swift test` process, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` failed with `-25308` / `AKSError=-536870174`
(`kIOReturnNotPermitted`), while `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and the no-argument initialiser
worked. Likely cause is this headless, possibly screen-locked, unsigned test host rather than the API; it needs
re-checking in a signed app on an iPhone. Tests use `AfterFirstUnlockThisDeviceOnly`.

## ECDSA behaviour

- **Non-deterministic.** CryptoKit (software and SE) randomises k: two signatures over the same message differ
  (tested for both). Vectors therefore check *verification* (`sign` cases), never exact signature bytes. The
  reference signs with RFC 6979 only so the vector file is reproducible; the spec already says real signers may
  randomise.
- **No low-s normalisation.** 112 of 200 SE signatures over distinct messages had the top bit of `s` set, so
  roughly half of Secure Enclave signatures are "high-s". Verifiers MUST NOT reject high-s. This matches the spec
  (`high_s_twin_verifies` is `valid: true`).
- **Malleability.** CryptoKit and `cryptography` both accept the twin `(r, n-s)`; the SE and software fixtures are
  checked for this in Python (`test_signature_s_malleability`) and Swift checks the vector twin
  (`testHighSTwinIsAcceptedByCryptoKit`). Hence the existing rule: a signature is never an identifier, dedupe key or
  replay token.
- **Vector `sign` section:** CryptoKit agrees with every case including the rejections (other key, changed
  message, 126-byte signature, `r = 0`, `s = n`, off-curve key). The malformed ones are rejected by CryptoKit either
  at `ECDSASignature(rawRepresentation:)` / `PublicKey(x963Representation:)` or by `isValidSignature`; the app
  should still apply the spec's explicit length and range check first so behaviour does not depend on CryptoKit.
- **DER vs raw.** CryptoKit's `rawRepresentation` is already the protocol's 64-byte `r||s`. DER is only needed for
  Security-framework calls (`SecKeyCreateSignature` returns DER) and for OpenSSL/`cryptography`'s `verify`; the Python
  tests convert both ways and compare.
- Throughput: about 5 ms per SE signature on this Mac.

## Interop evidence

Swift to Python (committed fixture `spikes/s1/fixtures/se-mac.json`, verified by `tests/spikes/test_s1_vectors.py`):

- SE signing key, 3 messages: raw and DER both verify through `ref` `SuiteP.verify` and `cryptography`; DER and raw
  encode the same `(r, s)`; the high-s twin verifies.
- SE key-agreement key against vector key `laptop.kx`: the SE-computed shared secret equals what Python computes
  from the SE public key and the vector private key.
- Seal with the **SE key as the sender's ephemeral key**, recipient the vector key `phone.kx`: `ref.open_sealed` opens
  it (so ECDH, `salt = eph_pub || rcpt_pub`, the `kdf_seal` info and the AAD all agree), and a tampered blob fails.
- Same for a software CryptoKit signer and sealer.

Python to Swift (vectors): all software vector checks above, and in `swift test` the SE recipient path
(`testSealToAndFromSecureEnclave`) round-trips a software-sealed message through an SE key-agreement key and the
reverse. A seal produced in Python *to an SE public key* is not committed, because an SE key cannot be recreated
across runs; the equal shared secret plus the identical sealing code path is the evidence.

## Protocol caveats and findings for the contract

1. **Vector `seed` is not the private scalar.** `ref` derives `d = int(seed) mod (n-1) + 1`
   (`SuiteP._priv`), so importing the 32 bytes straight into CryptoKit gives a different key. `S1Support.scalar(fromSeed:)`
   does the mapping. Worth one sentence in `docs/protocol-v2.md` §1 / the vector README so a third implementation
   (the Swift app's own test target) does not trip.
2. **Suite 2 is described as the "fallback" (D22, `docs/protocol-v2.md` §1 table and around line 1716) while D46 makes it the
   one suite.** Wording only; no behaviour change. Suite 1 (Ed25519/X25519) is impossible in the Secure Enclave,
   which supports P-256 only.
3. **Signing and key agreement are separate SE key types** in CryptoKit (`SecureEnclave.P256.Signing` vs
   `.KeyAgreement`). The protocol already has separate `dk_sig_pub` and `dk_kx_pub`, so nothing changes. Do not
   plan on one key for both.
4. **No private key backup or migration**: see above. A new phone is a new device enrolment.
5. **Verifiers must accept high-s and must range-check** (`1 <= r,s < n`, length 64) themselves; do not rely on
   what CryptoKit throws.
6. `SecureEnclave.isAvailable` is true in the Simulator here; gate production policy on a real attestation or
   on the build target, not on that flag.

## How to reproduce

```
# T0 (each < 30 s)
cd spikes/s1 && swift test --filter SoftwareP256Tests
cd spikes/s1 && swift test --filter SecureEnclaveTests
uv run pytest tests/spikes/test_s1_vectors.py -x -q

# T1
cd spikes/s1 && swift test                                   # macOS, 20 tests
xcrun simctl create "S1 iPhone 16" com.apple.CoreSimulator.SimDeviceType.iPhone-16 \
  com.apple.CoreSimulator.SimRuntime.iOS-18-3                # once; no iPhone existed on this machine
cd spikes/s1 && xcodebuild test -scheme S1 \
  -destination 'platform=iOS Simulator,OS=18.3.1,name=S1 iPhone 16'
uv run pytest -q

# regenerate the fixture (needs a Secure Enclave Mac); ECDSA is random, so the file changes every time
cd spikes/s1/tool && swift run s1-fixtures
cd spikes/s1/tool && swift run s1-fixtures --presence        # MANUAL: prompts for Touch ID / passcode
```

- Vector file location: env `S1_VECTORS`, else `tests/vectors_v2.json` resolved from the source file path (works in
  `swift test` and in the Simulator, which runs on the host filesystem).
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
