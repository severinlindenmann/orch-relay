import Darwin
import Foundation
import os
import PushCore

// SPIKE ONLY. Production (P4) keeps K_push(ws, e) and the pinned wsk_pub in the keychain, in a shared access group
// (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, not synchronizable, no biometry/user-presence flags), and
// WK_e in a stricter app-only item. Plain files in the App Group container are included in backups.

let appGroupID = "group.io.severin.orch"
let orchLog = Logger(subsystem: "io.severin.orch", category: "push")   // never log labels, ids, kinds or keys

struct StoreError: Error { let why: String }

/// The shared container (App Group only: no private-Library fallback, no bundled key material).
struct SpikeStore {
    let dir: URL?
    var usesGroup: Bool { dir != nil }

    init() { dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) }

    private func url(_ n: String) throws -> URL {
        guard let d = dir else { throw StoreError(why: "no_group") }
        return d.appendingPathComponent(n)
    }

    func materialURL() throws -> URL { try url("material.json") }
    func logURL() throws -> URL { try url("nse-log.jsonl") }
    func selftestURL() throws -> URL { try url("selftest-result.jsonl") }

    /// Material = {ws, wsk_pub, k_push: {epoch: hex}}. nil if missing or malformed (the caller then fails closed).
    func loadMaterial() -> [String: PushOpener.WorkspaceKeys]? {
        guard let u = try? materialURL(), let d = try? Data(contentsOf: u),
              let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let ws = o["ws"] as? String, let pub = o["wsk_pub"] as? String, let kj = o["k_push"] as? [String: String],
              let pubData = B64U.decode(pub) else { return nil }
        var k: [Int: Data] = [:]
        for (e, h) in kj { if let ei = Int(e), let kd = Hex.decode(h, length: 32) { k[ei] = kd } }
        return k.isEmpty ? nil : [ws: .init(wskPub: pubData, kPush: k)]
    }

    /// Cross-process exclusive lock (flock on a lock file in the container) around load -> open -> durable write.
    func withLock<T>(_ body: () throws -> T) throws -> T {
        let fd = open(try url("last-shown.lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw StoreError(why: "lock_open") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw StoreError(why: "lock") }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    /// Absent file = empty table (first run). Any other read or parse error throws (fail closed).
    func loadLast() throws -> [String: Int64] {
        let u = try url("last-shown.json")
        guard FileManager.default.fileExists(atPath: u.path) else { return [:] }
        guard let d = try? Data(contentsOf: u), let o = try? JSONSerialization.jsonObject(with: d) as? [String: NSNumber] else {
            throw StoreError(why: "last_unreadable")
        }
        return o.mapValues { $0.int64Value }
    }

    /// Atomic replace, protection class "until first user authentication" (the NSE runs while the phone is
    /// locked, so never `Complete`), excluded from backup, then F_FULLFSYNC. Throws on any failure.
    func saveLast(_ l: [String: Int64]) throws {
        var u = try url("last-shown.json")
        let d = try JSONSerialization.data(withJSONObject: l)
        do { try d.write(to: u, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]) }
        catch { throw StoreError(why: "last_write") }
        var rv = URLResourceValues(); rv.isExcludedFromBackup = true
        try? u.setResourceValues(rv)
        let fd = open(u.path, O_RDONLY)
        guard fd >= 0 else { throw StoreError(why: "last_sync") }
        defer { close(fd) }
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw StoreError(why: "last_sync") }
    }

    /// Refusal reasons and counts only (no content).
    func appendLog(_ line: [String: Any]) {
        guard let u = try? logURL(), var d = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]) else { return }
        d.append(0x0A)
        if let h = try? FileHandle(forWritingTo: u) { h.seekToEndOfFile(); h.write(d); try? h.close() } else { try? d.write(to: u) }
    }

    func appendSelfTest(_ line: [String: Any]) {
        guard let u = try? selftestURL(), var d = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]) else { return }
        d.append(0x0A)
        if let h = try? FileHandle(forWritingTo: u) { h.seekToEndOfFile(); h.write(d); try? h.close() } else { try? d.write(to: u) }
    }
}
