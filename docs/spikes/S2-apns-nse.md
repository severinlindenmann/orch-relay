# Spike S2: APNs and a notification service extension (NSE)

Refs severinlindenmann/orch-relay#4 (the issue body still describes a PWA / Web Push; decisions D45 native app,
D46 P-256 suite 2, D47 APNs with the auth key on the relay replace it). Bundle ids per the owner decision:
app `io.severin.orch`, NSE `io.severin.orch.notify`, App Group `group.io.severin.orch`.

## Result in one paragraph

The decrypt-verify-rewrite path works: `PushCore` (CryptoKit only) opens every `push.cases` vector of suite 2
with the expected result, and the real NSE class, fed with the generated APNs payloads inside the Simulator,
decrypts a sealed question, falls back to "New activity" for tampered / forged-by-member-device / stale pushes,
and replaces the question notification with "Answered on laptop". **The Simulator cannot show that the NSE
process is started by a push**: `xcrun simctl push` injects a local-style `addRequest` through
CoreSimulatorBridge and never launches the extension (iOS 18.3.1 and iOS 27.0, Xcode 27). That, plus real APNs
(`apns-collapse-id`, time limit, killing the extension), needs a real iPhone and the Apple account.

## What was built

| Path | What |
|---|---|
| `spikes/s2/PushCore` | Swift package, CryptoKit only. `PushOpener.open(raw:keys:last:nowMs:)` = section 9 for suite 2, same check order as `sw_open_push` in `ref/`. Strict JSON subset parser + canonical JSON, canonical b64u/hex, HKDF `kdf_push`, SALTED-AEAD open, ECDSA P-256 raw `r\|\|s` with range check (1..n-1), high-s accepted, on-curve public key check. |
| `spikes/s2/PushCore/Tests` | XCTest: all `suites["2"].push.cases` (11 cases, exact result and reason), all suite 2 `sign` vectors (incl. `high_s_twin_verifies`), strict-JSON rejections. |
| `spikes/s2/App` | `project.yml` (xcodegen; the `.xcodeproj` is generated and not committed), app `OrchApp` (SwiftUI, iOS 18) and `OrchNSE` (`UNNotificationServiceExtension`). |
| `spikes/s2/make_push.py` | Writes the five `.apns` files and `demo_material.json` from `ref/` and the vector material of workspace A. |
| `tests/spikes/test_s2_payloads.py` | The payloads open (or are refused for the intended reason) with `ref`, stay under 4 KB / 3 KB. |
| `e2e/ios/s2-run.sh <udid>` | Build, install, send the five pushes with `simctl push`, then run the in-process NSE self-test; prints the os_log lines and writes screenshots to `spikes/s2/out/shots`. |

The NSE: reads `userInfo["o"]`, re-serialises it (sorted keys), calls `PushOpener`, on `show` sets
title/body from the inner payload (`question.closed` -> title "Answered"), stores `orch_id` in `userInfo`,
and for `question.closed` removes delivered notifications with the same `orch_id` before delivering. On
any `drop` it delivers "orch / New activity" (the relay's own generic text, never sealed content). The "last
shown ts per (ws, id)" table and the material live in the App Group container; the app copies the bundled demo
material into it at launch (stand-in for pairing). The NSE falls back to its own bundled copy and logs which one
it used (`material=group` in all runs).

## Capability matrix

| Capability | Simulator (iOS 18.3.1 and 27.0, Xcode 27) | Real iPhone + APNs |
|---|---|---|
| App + NSE build and install unsigned | Yes: `CODE_SIGN_IDENTITY="-"` (ad-hoc, via xcodegen settings), no team, no profile. The NSE is registered with PlugInKit/LaunchServices (log: `plugin INSTALLED io.severin.orch.notify`). | Needs the Apple account, provisioning, the push entitlement. |
| `simctl push` starts the NSE | **No.** 5 pushes with `mutable-content: 1` on both runtimes: `usernotificationsd` logs `[CoreSimulatorBridge] Forwarding addRequest`, no `OrchNSE` process, no NSE log line, the delivered notification still reads "orch / New activity" (aps.alert). Treat `simctl push` as a local notification. | Yes (to verify via TestFlight). |
| NSE code decrypt/verify/rewrite | **Yes, in-process**: the app links `NotificationService.swift` and calls `didReceive` with a built `UNNotificationRequest` (`-nse-selftest <dir>`). Not the extension process, so memory/sandbox/time limits are not exercised. | Yes (to verify). |
| App Group container shared between app and NSE | **Yes, unsigned/ad-hoc**: `containerURL(forSecurityApplicationGroupIdentifier:)` returned a real container (`Containers/Shared/AppGroup/<uuid>`) with ad-hoc signing and the entitlement; app wrote `material.json`, the in-process NSE read it. Cross-process (NSE process) sharing could not be observed because the NSE never starts. | Needs the App Group registered in the developer account. |
| Shared keychain access group | Not tried (keychain-access-groups need a team-prefixed group; the file-in-container route is enough for the spike). Material in a plain file is fine for the spike only: on the phone `WK_e` must sit in the keychain (`kSecAttrAccessGroup`, `AfterFirstUnlock`, no biometry) because the NSE runs while the phone is locked. | To verify. |
| Replacement ("answered elsewhere") | **Works by identifier and by NSE removal**: a local request with the same identifier replaces the earlier one (this is what `apns-collapse-id` becomes); the NSE additionally removes by `orch_id`. Evidence below. `simctl push` itself cannot set `apns-collapse-id`: the identifier is a fresh UUID. | `apns-collapse-id` (max 64 bytes) replaces on the device before the NSE runs; the NSE removal is the backup and covers the case where the question was already shown without collapse id. |
| Banner/lock screen screenshot | No: Xcode 27 ships no `Simulator.app` (`open -a Simulator` fails) and `simctl` has no tap, so the permission prompt cannot be answered. The app asks for **provisional** authorization (no prompt, granted=true); notifications go to the list quietly. Evidence is the app's own delivered-notification list and os_log. | A normal alert authorization; banner visible. |
| Background wake / `content-available` | Not testable. The design does not need it: alerts with `mutable-content`. | Silent pushes are throttled; not used. |
| NSE time limit | Not testable (about 30 s on iOS; `serviceExtensionTimeWillExpire` delivers the generic text, implemented). Work is HKDF + AES-GCM + one P-256 verify + two small file reads: milliseconds. | To measure. |
| NSE memory limit | Not testable (about 24 MB on iOS). CryptoKit use is small. | To measure on a device. |
| Payload size | Typical question push: **508 bytes** APNs JSON, 362 bytes outer object (limit 4096 / 3072). Worst case (80 code points of 4-byte characters = 320 bytes label) adds about 430 bytes after base64: still under 1.2 KB. | Same. |

## Evidence (this machine, Xcode 27.0, `S2 iPhone 16` on iOS 18.3.1)

`simctl push` (e2e/ios/s2-run.sh, first part): after each push the app's delivered list shows
`orch | New activity`, `NSE didReceive` never appears in `log show --predicate 'subsystem == "io.severin.orch"'`
(only `app launched ... uses group container: true` and `notification authorization granted=true`). Same on
iOS 27.0 (`S2 iPhone 16 (27)`): the screenshot shows "Delivered notifications (1): orch | New activity".

In-process NSE self-test (`-nse-selftest`), log lines, fresh install:

```
NSE didReceive id=cid-q-0167f4bf37be9ccc group=true
NSE show kind=question id=q-0167f4bf37be9ccc label=Ship L-0042? material=group
selftest 01_question.apns -> title=orch body=Ship L-0042? collapse=cid-q-0167f4bf37be9ccc
NSE drop why=tag          (02_tampered)   -> body=New activity
NSE drop why=signature    (03_forged_by_member_device) -> body=New activity
NSE drop why=stale        (04_stale_25h)  -> body=New activity
NSE show kind=question.closed id=q-0167f4bf37be9ccc label=Answered on laptop material=group
NSE replace: removing 1 delivered with orch_id=q-0167f4bf37be9ccc
selftest delivered now: cid-q-0167f4bf37be9ccc=Answered on laptop ; cid-04...=New activity ; cid-03...=New activity ; cid-02...=New activity
```

The question notification "Ship L-0042?" is gone after the closed push; only "Answered on laptop" remains under the
same identifier. (os_log in the spike uses `privacy: .public` so the lines are visible; the real NSE must not log
labels.)

## Reproduction

```
cd spikes/s2/PushCore && swift test                         # 3 tests, all suite 2 push cases
uv run pytest tests/spikes/test_s2_payloads.py -q           # payloads, sizes
brew install xcodegen
xcrun simctl create "S2 iPhone 16" com.apple.CoreSimulator.SimDeviceType.iPhone-16 com.apple.CoreSimulator.SimRuntime.iOS-18-3
e2e/ios/s2-run.sh <udid>       # build, simctl push x5, then the in-process NSE self-test, prints logs
xcrun simctl spawn <udid> log show --predicate 'subsystem == "io.severin.orch"' --last 5m --style compact --info
```

## Proposal: APNs payload shape for section 9

```
{ "aps": { "alert": {"title": "orch", "body": "New activity"},   // generic, from the relay; shown if the NSE fails
           "mutable-content": 1,
           "thread-id": "<ws hex>",                              // groups by workspace; ws is already visible to the relay
           "sound": "default" },
  "o": { "v": 2, "ws": "<hex>", "epoch": 1, "c": "<b64u>" } }    // the section 9 outer object, as a JSON object
```

- The sealed object goes in one custom top-level key `o` as a JSON object (about 30 percent smaller than a string
  holding escaped JSON; the NSE re-serialises it with sorted keys, which equals `cj` for this flat object).
  Whatever is in `aps.alert` is untrusted relay text, so it must be generic.
- Headers the relay sends: `apns-push-type: alert`, `apns-topic: io.severin.orch` (the NSE needs no own topic),
  `apns-priority: 10` (user-visible), `apns-expiration`: the payload's own 24 h age limit is checked on the
  device from `ts_ms`; set the header to now + 24 h so APNs does not deliver older ones, and `0` is wrong
  (it means "do not store"). `apns-collapse-id`: see the finding below.
- Auth: token-based (`.p8` + key id + team id, ES256 JWT) on the relay only; the device token is registered by the
  phone with the relay per device. Sandbox vs production host depends on the build (TestFlight and App Store
  use production).

## Findings for the contract

1. **Section 9 still says "Web Push payload", "The service worker"** and `tag = id`. Rename to the native
   path: APNs payload key `o`, "the notification service extension", replacement by collapse id.
2. **The relay cannot compute `apns-collapse-id` from the sealed object**: `id` is inside `c`. Options: (a) the host
   supplies an opaque `collapse` value in its relay publish call, e.g. `b64u(HMAC(K_push, "orch/v2/push-collapse|"
   || id))[:22]` (at most 64 bytes, stable per question, unlinkable to the id by the relay, though the relay can
   already link question and closed push by that value, which it could do by timing anyway); (b) no collapse id,
   replacement only by the NSE removing `orch_id`. Recommend (a) plus (b) as backup. This needs an optional field in
   the host-to-relay push request (not in the sealed object, which stays `{v, ws, epoch, c}`).
3. **`question.closed` as its own push works with the existing rules**: it carries the same `id` and a higher
   `ts_ms`, so section 9 rule 7 (higher than the last shown) accepts it and the replay rule rejects the
   older question after it (vector `older_after_newer_for_the_same_id`). If the question push arrives after the
   closed one, it is refused, so a late question is never shown after the answer.
4. **Last-shown table needs a store the NSE can write** (App Group file or keychain) and the NSE can run twice in
   parallel for two pushes; the spike does a read-modify-write on a file without locking. The real implementation
   needs a lock (`flock`) or a keychain-backed counter.
5. **`ts_ms` accepts up to now + 300 s and at most 24 h old**; APNs can hold a push for hours while the phone is
   off, so a late but valid question is still shown up to 24 h later. That matches the intent.
6. **Size is no issue**: 508 bytes typical against 4096 (the 3072 cap in section 9 can stay, it is conservative).
7. **Fallback text is the relay's**: if iOS does not run the NSE (killed, low memory, extension crash) the user sees
   the generic `aps.alert`. Section 9 should say that this text is a fixed string and must not contain sealed content.
8. **Unverified on a device**: whether `mutable-content` pushes are delivered to the NSE while the phone is locked
   and before first unlock (keychain class `AfterFirstUnlock` is required for `WK_e`), the time and memory limits,
   `apns-collapse-id` replacement, and token-based APNs auth with the real key.

## Pending (needs the Apple account)

- Real APNs delivery with the auth key on the relay (sandbox, then TestFlight/production).
- NSE running as its own process on a real iPhone: decrypt + verify with `WK_e` read from the shared keychain while
  locked; measure runtime and memory; confirm collapse-id replacement and the NSE removal fallback.
- Replace the plain-file material with the keychain access group.
