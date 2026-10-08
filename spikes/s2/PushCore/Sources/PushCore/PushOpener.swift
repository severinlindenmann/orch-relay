import CryptoKit
import Foundation

/// Protocol v2 section 9, suite 2 (P-256) only. Everything the notification service extension does with a push
/// before it may show text. Mirrors ref/orch_protocol_ref.py `sw_open_push`, including the order of the checks.
public enum PushOpener {
    public static let suiteID: UInt8 = 2
    public static let maxPush = 3072
    public static let maxAgeMs: Int64 = 24 * 3600 * 1000
    public static let skewMs: Int64 = 300_000
    public static let maxLabel = 80
    public static let kinds: Set<String> = ["question", "question.closed", "ticket.update", "drop.new", "peer.ticket", "join"]

    public struct WorkspaceKeys {
        public var wskPub: Data                // 65-byte uncompressed P-256 point
        public var kPush: [Int: Data]          // epoch -> K_push(ws, e) (32 bytes): all a push receiver needs, not WK_e
        public init(wskPub: Data, kPush: [Int: Data]) { self.wskPub = wskPub; self.kPush = kPush }
        /// Derive K_push(ws, e) from WK_e (what the host or the app does once, at pairing / epoch change).
        public init(wskPub: Data, wsHex: String, wk: [Int: Data]) {
            self.init(wskPub: wskPub, kPush: wk.reduce(into: [:]) { $0[$1.key] = PushOpener.deriveKPush(wk: $1.value, wsHex: wsHex, epoch: $1.key) })
        }
    }

    public struct Payload: Equatable {
        public let kind: String, id: String, label: String, tsMs: Int64
    }

    public enum Result: Equatable {
        case show(Payload)
        case drop(String)   // why: size, shape, no_key, tag, signature, payload, stale, replay (as in the vectors)
    }

    /// `last` maps "<ws hex>/<id>" to the highest ts_ms shown; it is updated on `.show` only.
    public static func open(raw: Data, keys: [String: WorkspaceKeys], last: inout [String: Int64], nowMs: Int64) -> Result {
        if raw.count > maxPush { return .drop("size") }
        guard let m = try? StrictJSON.parse(raw).object, Set(m.keys) == ["v", "ws", "epoch", "c"], m["v"] == .int(2),
              let wsHex = m["ws"]?.string, let ws = Hex.decode(wsHex, length: 16),
              let cStr = m["c"]?.string, let c = B64U.decode(cStr) else { return .drop("shape") }
        guard let epoch = m["epoch"]?.int, epoch >= 0, epoch <= Int64(UInt32.max),
              let entry = keys[wsHex], let kPushData = entry.kPush[Int(epoch)] else { return .drop("no_key") }

        let e32 = UInt32(epoch)
        let eBytes = Data([UInt8(e32 >> 24), UInt8((e32 >> 16) & 255), UInt8((e32 >> 8) & 255), UInt8(e32 & 255)])
        let kPush = SymmetricKey(data: kPushData)
        let aad = Data("orch/v2/push-aad|".utf8) + Data([suiteID]) + ws + eBytes

        guard c.count >= 32, let plain = try? saltedOpen(kBase: kPush, msgLabel: Data("orch/v2/push-msg".utf8), aad: aad, blob: c),
              let innerV = try? StrictJSON.parse(plain) else { return .drop("tag") }
        guard let inner = innerV.object, Set(inner.keys) == ["p", "sig"], case .object(let p)? = inner["p"] else { return .drop("payload") }
        guard let sigStr = inner["sig"]?.string, let sig = B64U.decode(sigStr, length: 64) else { return .drop("tag") }

        let signed = Data("orch/v2/sig/push|".utf8) + Data([suiteID]) + ws + eBytes + canonicalJSON(.object(p))
        guard verifyP256(pub: entry.wskPub, sig: sig, msg: signed) else { return .drop("signature") }

        guard Set(p.keys) == ["kind", "id", "label", "ts_ms"], let kind = p["kind"]?.string, kinds.contains(kind),
              let label = p["label"]?.string, label.unicodeScalars.count <= maxLabel,
              let id = p["id"]?.string, let ts = p["ts_ms"]?.int else { return .drop("payload") }
        guard ts >= nowMs - maxAgeMs, ts <= nowMs + skewMs else { return .drop("stale") }
        let key = lastKey(wsHex: wsHex, id: id)
        if let prev = last[key], ts <= prev { return .drop("replay") }
        last[key] = ts
        return .show(Payload(kind: kind, id: id, label: label, tsMs: ts))
    }

    /// Key of the "last shown" table: ws hex, "/", hex of the id's UTF-8 bytes (Swift String equality is
    /// canonical equivalence, ref compares code points, so never key by the String itself).
    public static func lastKey(wsHex: String, id: String) -> String { "\(wsHex)/\(Hex.encode(Data(id.utf8)))" }

    public static func deriveKPush(wk: Data, wsHex: String, epoch: Int) -> Data {
        hkdf(ikm: wk, salt: Data(), info: Data("orch/v2/push|\(wsHex)|\(epoch)".utf8)).withUnsafeBytes { Data($0) }
    }

    // MARK: primitives

    static func hkdf(ikm: Data, salt: Data, info: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: 32)
    }

    /// SALTED-AEAD open: salt(16) || AES-256-GCM(HKDF(K, salt, msg_label), nonce = 12 zero bytes, aad).
    static func saltedOpen(kBase: SymmetricKey, msgLabel: Data, aad: Data, blob: Data) throws -> Data {
        let b = Data(blob)
        let salt = b.prefix(16)
        let ctTag = b.dropFirst(16)
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: kBase, salt: salt, info: msgLabel, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(repeating: 0, count: 12)),
                                        ciphertext: ctTag.dropLast(16), tag: ctTag.suffix(16))
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }

    /// ECDSA P-256 / SHA-256, raw r||s. Range-check r and s in 1..n-1; high-s is accepted (section 1.2).
    public static func verifyP256(pub: Data, sig: Data, msg: Data) -> Bool {
        guard pub.count == 65, pub.first == 0x04, sig.count == 64 else { return false }
        let n = [UInt8](hexBytes: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        for half in [Array(sig.prefix(32)), Array(sig.suffix(32))] {
            if half.allSatisfy({ $0 == 0 }) { return false }
            if !half.lexicographicallyPrecedes(n) { return false }   // >= n
        }
        guard let key = try? P256.Signing.PublicKey(x963Representation: pub),        // on-curve check
              let s = try? P256.Signing.ECDSASignature(rawRepresentation: sig) else { return false }
        return key.isValidSignature(s, for: msg)
    }
}

extension Array where Element == UInt8 {
    init(hexBytes h: String) {
        let u = Array(h.utf8)
        self = stride(from: 0, to: u.count, by: 2).map { UInt8(String(decoding: u[$0..<$0 + 2], as: UTF8.self), radix: 16)! }
    }
}
