import Foundation
import os
import PushCore

let appGroupID = "group.io.severin.orch"
let orchLog = Logger(subsystem: "io.severin.orch", category: "push")

/// Where the demo material and the "last shown" table live. The app group container if the process has the
/// entitlement, else the process's own Library (a spike fallback that records the limitation).
struct SharedStore {
    let dir: URL
    let usesGroup: Bool

    init() {
        if let g = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            dir = g; usesGroup = true
        } else {
            dir = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]; usesGroup = false
        }
    }

    var materialURL: URL { dir.appendingPathComponent("material.json") }
    var lastURL: URL { dir.appendingPathComponent("last-shown.json") }
    var logURL: URL { dir.appendingPathComponent("nse-log.jsonl") }

    func loadLast() -> [String: Int64] {
        guard let d = try? Data(contentsOf: lastURL),
              let o = try? JSONSerialization.jsonObject(with: d) as? [String: NSNumber] else { return [:] }
        return o.mapValues { $0.int64Value }
    }

    func saveLast(_ l: [String: Int64]) {
        if let d = try? JSONSerialization.data(withJSONObject: l) { try? d.write(to: lastURL, options: .atomic) }
    }

    func appendLog(_ line: [String: Any]) {
        guard var d = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]) else { return }
        d.append(0x0A)
        if let h = try? FileHandle(forWritingTo: logURL) {
            h.seekToEndOfFile(); h.write(d); try? h.close()
        } else { try? d.write(to: logURL) }
    }

    /// Material = {ws, wsk_pub, wk}. Group copy (provisioned by the app) wins; falls back to the bundle copy.
    func loadMaterial(bundle: Bundle) -> (keys: [String: PushOpener.WorkspaceKeys], source: String)? {
        for (url, src) in [(materialURL, usesGroup ? "group" : "private"), (bundle.url(forResource: "demo_material", withExtension: "json"), "bundle")] {
            guard let url, let d = try? Data(contentsOf: url),
                  let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let ws = o["ws"] as? String, let pub = o["wsk_pub"] as? String, let wkj = o["wk"] as? [String: String],
                  let pubData = B64U.decode(pub) else { continue }
            var wk: [Int: Data] = [:]
            for (e, h) in wkj { if let ei = Int(e), let k = Hex.decode(h, length: 32) { wk[ei] = k } }
            return ([ws: .init(wskPub: pubData, wk: wk)], src)
        }
        return nil
    }
}
