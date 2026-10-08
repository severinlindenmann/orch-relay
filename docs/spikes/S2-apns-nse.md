# Spike S2: APNs and a notification service extension (NSE)

Refs severinlindenmann/orch-relay#4 (the issue body still describes a PWA / Web Push; decisions D45 native app,
D46 P-256 suite 2, D47 APNs with the auth key on the relay replace it). Bundle ids per the owner decision:
app `io.severin.orch`, NSE `io.severin.orch.notify`, App Group `group.io.severin.orch`.
Reviewed by Opus (security) and Sonnet (code); their findings are folded in below.

## Result in one paragraph

`PushCore` (CryptoKit only) opens every `push.cases` vector of suite 2 with the expected result. The NSE class,
**compiled into the app and called directly (not run as the extension process)**, decrypts a sealed question,
shows fixed generic text for tampered / forged-by-member-device / stale / replayed pushes, never carries any
relay-chosen content, and replaces the question notification when `question.closed` arrives. **The Simulator
cannot show that a push starts the NSE process**: `xcrun simctl push` injects a local-style `addRequest` through
CoreSimulatorBridge and never launches the extension (iOS 18.3.1 and 27.0, Xcode 27). Sandbox, entitlements, the
extension point, time and memory limits, locked-phone keychain, `apns-collapse-id` and real APNs need a real
iPhone and the Apple account.

## What was built

| Path | What |
|---|---|
| `spikes/s2/PushCore` | Swift package, CryptoKit only. `PushOpener.open(raw:keys:last:nowMs:)` = section 9 for suite 2, same check order as `sw_open_push` in `ref/`, on the exact bytes it is given. Strict JSON subset parser + canonical JSON (UTF-8 validated without altering bytes, so a leading U+FEFF is kept), canonical b64u/hex, HKDF, SALTED-AEAD open, ECDSA P-256 raw `r\|\|s` with range check, high-s accepted, on-curve key check. The receiver holds `K_push(ws,e)`, not `WK_e`; the "last shown" table is keyed by `ws` + hex of the id's UTF-8 bytes (Swift `String` equality is canonical equivalence). |
| `spikes/s2/PushCore/Tests` | XCTest: all suite 2 `push.cases` (exact result and reason), suite 2 `sign` vectors incl. high-s, strict JSON rejections, BOM kept, key by UTF-8 bytes. The vector file is found by walking up from the test file; the error lists the searched paths. |
| `spikes/s2/App` | `project.yml` (xcodegen; `.xcodeproj` and `demo_material.json` are generated and gitignored), `OrchApp` (SwiftUI, iOS 18) and `OrchNSE`. |
| `spikes/s2/make_push.py` | Writes the five `.apns` files and `demo_material.json` from `ref/` and workspace A of the vectors. |
| `tests/spikes/test_s2_payloads.py` | The payloads open (or are refused for the intended reason) with `ref` on the exact `o` string, stay under 4 KB / 3 KB, carry no `thread-id`. |
| `e2e/ios/s2-run.sh <udid>` | bash, `set -euo pipefail`, shellcheck clean, preflight, cleanup trap. Build, install, `simctl push` x5, then the in-process NSE self-test; polls for `selftest done`; prints the self-test results and reason-only log. macOS + Xcode + a Simulator runtime; not run in CI. |

### NSE behaviour (reference for P4)

- `o` is a JSON **string** in the APNs payload; its UTF-8 bytes go to `PushOpener` unchanged, so the size, shape,
  duplicate-key and float rules of section 9 run on the real bytes (a dictionary re-serialised by iOS would hide
  them; the Opus differential run showed `epoch: 1.0` and a 3073-byte object being shown that way).
- **Fresh content on every path** (show, refuse, timeout): fixed generic text `orch / New activity`, or verified
  title/body; `threadIdentifier` set locally from the verified ws. Nothing of the relay's subtitle, category,
  thread, sound, attachments or `userInfo` is carried over. The self-test sends a request with
  `subtitle="RELAY SUBTITLE"`, category, thread and a `relay_marker` userInfo key: the output has empty
  subtitle/category, `relay_userinfo_carried: false`.
- Timeout (`serviceExtensionTimeWillExpire`) delivers the generic content; the handler runs **exactly once**
  (self-test `race_timeout_x2` -> `handler_calls: 1`).
- Replay table: `flock` on a lock file in the container around load -> section 9 rules -> prune (older than
  24 h + 300 s) -> atomic write + `F_FULLFSYNC` -> **then** show. A read error other than "file absent", or a
  write error, shows the generic text (fail closed). Protection class until-first-user-authentication, excluded
  from backup.
- "Answered elsewhere" removes delivered notifications whose `orch_key` equals `"<ws>/<id>"` (compared as UTF-8
  bytes), not by id alone, so one workspace cannot remove another's notification.
- Logging: refusal reasons and counts only (`NSE refuse why=tag`). No label, id, kind, key or request id.
- Spike-only: material is a file in the App Group (K_push + `wsk_pub`, no `WK_e`, no bundled fallback in the NSE;
  the app provisions it from a bundled test JSON). Production: keychain, below.

## Capability matrix

| Capability | Simulator (iOS 18.3.1 and 27.0, Xcode 27) | Real iPhone + APNs |
|---|---|---|
| App + NSE build and install unsigned | Yes: ad-hoc signing (`CODE_SIGN_IDENTITY="-"`), no team/profile. The NSE is registered (`pluginkit -m -i io.severin.orch.notify` lists it). | Needs the Apple account, provisioning, push entitlement. |
| `simctl push` starts the NSE | **No** (see "How to check"). | To verify. |
| NSE code decrypt/verify/rewrite | Yes, **in-process** (class compiled into the app, called directly). Not the extension process: sandbox, entitlements, memory/time limits and the extension point are untested. | To verify as its own process. |
| App Group container | Yes with ad-hoc signing and the entitlement: `containerURL(forSecurityApplicationGroupIdentifier:)` returns a real container; the app wrote the material, the in-process NSE read it and wrote the table under `flock`. Cross-process use by the NSE process could not be observed. | Group must be registered in the account. |
| Shared keychain access group | Not tried. | To verify (production storage). |
| Replacement | Works in the harness: a request re-added with the same identifier replaces the earlier one, and the NSE removes by `(ws,id)`. **The identifier is chosen by the harness**, so this does not test `apns-collapse-id`. `simctl push` cannot set a collapse id. | `apns-collapse-id` (max 64 bytes) to verify; NSE removal is the backup. |
| Banner screenshot | No: Xcode 27 ships no `Simulator.app` and `simctl` has no tap. The app uses provisional authorization (no prompt). Evidence is the self-test result file, os_log reasons and the app's delivered list. | Normal alert authorization; banner visible. |
| Background wake, time limit (~30 s), memory limit (~24 MB), locked-phone behaviour | Not testable. The work is HKDF + AES-GCM + one P-256 verify + two small file operations: milliseconds. | To measure. |
| Payload size | Typical question push **475 bytes** APNs JSON (outer object 362 bytes); limits 4096 / 3072. Worst case (80 four-byte characters) about 1.2 KB. | Same. |

## How to check that `simctl push` does not start the NSE

```
DEV=<udid>; B=io.severin.orch
xcrun simctl install $DEV <path>/OrchApp.app && xcrun simctl launch $DEV $B && xcrun simctl terminate $DEV $B
xcrun simctl push $DEV $B spikes/s2/out/01_question.apns
# 1. the push entered as a local-style request through the bridge (count >= 1)
xcrun simctl spawn $DEV log show --predicate 'process == "usernotificationsd" AND eventMessage CONTAINS "Forwarding addRequest: io.severin.orch"' --last 1m --style compact --info | grep -c addRequest
# 2. no NSE process ever ran (0 lines)
xcrun simctl spawn $DEV log show --predicate 'process == "OrchNSE"' --last 2m --style compact --info | grep -vc "^Timestamp\|getpwuid"
# 3. the extension IS registered, so it could have run
xcrun simctl spawn $DEV pluginkit -m -i io.severin.orch.notify
# 4. positive control: the same logging works when the NSE class runs in-process (prints NSE show / NSE refuse lines)
xcrun simctl launch $DEV $B -nse-selftest "$PWD/spikes/s2/out"
xcrun simctl spawn $DEV log show --predicate 'subsystem == "io.severin.orch"' --last 2m --style compact --info | grep "NSE "
```

After `simctl push`, opening the app shows `orch | New activity` (the relay's `aps.alert`) in its delivered list:
the notification arrived unmodified. The same holds on iOS 27.0; create that device with
`xcrun simctl create "S2 iPhone 16 (27)" com.apple.CoreSimulator.SimDeviceType.iPhone-16 com.apple.CoreSimulator.SimRuntime.iOS-27-0`
and pass its udid to `e2e/ios/s2-run.sh` (any installed runtime works).

## Evidence (Xcode 27.0, iOS 18.3.1)

Self-test result file (`selftest-result.jsonl`, the harness output; labels are not logged by the NSE):

```
01_question            body "Ship L-0042?"      subtitle "" category "" thread <ws> relay_userinfo_carried false
02_tampered            body "New activity"      (log: NSE refuse why=tag)
03_forged_by_member    body "New activity"      (why=signature)
04_stale_25h           body "New activity"      (why=stale)
05_question_closed     body "Answered on laptop"  (log: NSE replace removed=1; delivered list no longer has "Ship L-0042?")
race_timeout_x2        handler_calls 1          (replayed closed push + two timeouts)
```

## Reproduction

```
cd spikes/s2/PushCore && swift test                         # PushCore vectors and unit tests
uv run pytest tests/spikes/test_s2_payloads.py -q           # payloads, sizes
brew install xcodegen
xcrun simctl create "S2 iPhone 16" com.apple.CoreSimulator.SimDeviceType.iPhone-16 com.apple.CoreSimulator.SimRuntime.iOS-18-3
e2e/ios/s2-run.sh <udid>       # build, simctl push x5, in-process self-test, prints results
```

## Proposals (for the owner; nothing here changes the spec)

### APNs payload and relay (P3)

```
{ "aps": { "alert": {"title": "orch", "body": "New activity"},   // fixed, generic: shown whenever the NSE does not run
           "mutable-content": 1, "sound": "default" },           // no thread-id
  "o": "<cj(outer)>" }                                           // section 9 outer object as a JSON string, unchanged
```

- `o` as a **string** costs +14 bytes (362 -> 376; the earlier "30 percent smaller" claim for an object was wrong).
- No `thread-id`: it would hand Apple the workspace id per device token. The NSE sets `threadIdentifier` locally.
- Headers, identical for every kind: `apns-push-type: alert`, `apns-topic: io.severin.orch`, `apns-priority: 10`,
  `apns-expiration: now + 24 h` (0 would mean "do not store"). Uniform `sound`.
- `apns-collapse-id` only when the host supplies an optional opaque field (at most 64 bytes, outside the sealed
  object, never derived by the relay), only for `question` and `question.closed`:
  `K_collapse(e) = HKDF-SHA256(WK_e, "", ctx("orch/v2/push-collapse", ws, e))`,
  `collapse = b64u(HMAC-SHA256(K_collapse(e), "orch/v2/push-collapse-id|" || utf8(id)))[:22]` (132 bits). Register
  both labels in section 3. **Linkage trade-off:** the relay and Apple learn exact linkage of all pushes for one
  `(ws, id)` within an epoch (question -> closed pair, answer latency per question; for `ticket.update` every
  update of a ticket until epoch rotation, hence only the two question kinds). A malicious relay can reuse a
  collapse id to replace or hide a delivered notification (availability only, which it controls anyway). If the
  owner wants no new linkage, skip it: NSE removal by `(ws,id)` alone is the safer default; the cost is that an
  undelivered stale question is not collapsed by APNs before display (the replay rule still refuses it).
- Auth: token-based (`.p8`, key id, team id, ES256 JWT) on the relay only; keep it out of logs and process args.
  **Threat-model line:** custody of the APNs key equals the ability to show arbitrary text in the orch app (alerts
  without `mutable-content` skip the NSE), so the generic-text rule is a convention, not a guarantee, and nothing
  actionable may rest on notification text.

### Receiver rules (P4)

- No actionable notification categories (no approve/deny buttons on the lock screen). Do not trust `userInfo`,
  `aps.category` or any notification field on tap; tapping only opens the app, which re-verifies (`PushOpener` on
  `o`, or fetches from the host) and shows the verified question before any decision.
- The device signing key never signs from notification data (D49: no Face ID per signature, so this rule matters).
- Fresh content on every path; `(ws,id)` scoping; locked, durable, fail-closed last-shown table; no content logging
  (only refusal codes and timings); test the NSE as its own process on a device, locked, before and after first
  unlock.

### Storage (P4)

- Keychain only, shared access group `<TEAMID>.group.io.severin.orch`, class
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, not synchronizable, no user-presence/biometry flags (the NSE
  cannot prompt). The NSE-readable item holds **only `K_push(ws,e)`** per held epoch and the pinned `wsk_pub`;
  `WK_e` (bridge, wraps, grants) goes in a stricter app-only item (`WhenUnlockedThisDeviceOnly`).
- No plain files and no bundled fallback key material (backups include App Group files). The last-shown table may
  be a file (integrity, not secret; it reveals ids and timing): until-first-user-authentication, excluded from
  backup, never `Complete`. A backup restore resets it, bounded by the 24 h freshness window.

### Metadata and padding

- **Residual risk (document, accept):** Apple sees `o.ws`, `o.epoch` and an identical `c` fanned out to every
  device token of a workspace at the same instant, so it can build the cross-Apple-ID membership graph of each
  workspace even without `thread-id`. Hiding it would need a per-device push alias; identical `c` and timing
  would still link tokens.
- `|c|` reveals the kind and the label length (`join` vs `question.closed` differ by 11 bytes). Proposal: the host
  pads `cj(inner)` with trailing spaces to 1024 bytes before sealing. Both strict parsers accept trailing
  whitespace, so it is wire-compatible (1056 bytes -> about 1408 b64u characters, under 3072).

### Wording proposals (sections 9, 3, 5.2, 18)

- 9: "The relay forwards the outer object as the JSON **string** value of the APNs payload key `o`. The notification
  service extension applies rules 1-7 to that string's UTF-8 bytes." Replace "Web Push payload", "service
  worker", and `tag = id` (replacement is by collapse id and by `(ws,id)` removal).
- 9: "`aps.alert` is chosen by the relay and is shown whenever the extension does not run. It MUST be the fixed
  generic text. The receiver MUST NOT derive actions, navigation or decisions from any notification field other
  than a verified `o`."
- 9: "The receiver updates its last-shown record atomically (merge to the maximum) and durably before showing. If it
  cannot read or write that record it shows the generic text."
- 9 (optional): the `collapse` field and the two labels above (also section 3); host padding to 1024 bytes.
- 5.2 / D49: "A push-only receiver stores `K_push(ws,e)`, not `WK_e`."
- 18: Apple can link the device tokens of one workspace; the relay learns per-question linkage when collapse ids
  are used.
- Vector coverage: the 11 cases never exercise size, shape, label length, the +300 s boundary, a malformed `sig`,
  a non-JSON plaintext or a BOM; propose adding them to `push.cases` (both suites) in a P0 follow-up.

## Pending (needs the Apple account)

- Real APNs delivery with the auth key on the relay (sandbox, then TestFlight/production).
- The NSE as its own process on a real iPhone: `K_push` from the shared keychain while locked (before and after
  first unlock), runtime and memory, `apns-collapse-id` replacement, the NSE removal fallback.
- Replace the spike file storage with the keychain access group.
