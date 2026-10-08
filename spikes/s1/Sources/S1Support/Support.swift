import CryptoKit
import Foundation

// Protocol v2 suite 2 (P-256) helpers, CryptoKit only.

public enum S1Error: Error { case bad(String) }

public extension Data {
    init(hex: String) throws {
        guard hex.count % 2 == 0 else { throw S1Error.bad("odd hex length") }
        var out = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { throw S1Error.bad("bad hex") }
            out.append(b)
            i = j
        }
        self = Data(out)
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

// MARK: vectors

public enum Vectors {
    /// Resolution order: env S1_VECTORS, then <repo>/tests/vectors_v2.json relative to this source file
    /// (works in `swift test` and in the iOS Simulator, which runs on the host filesystem).
    public static func url() -> URL {
        if let p = ProcessInfo.processInfo.environment["S1_VECTORS"] { return URL(fileURLWithPath: p) }
        return repoRoot().appendingPathComponent("tests/vectors_v2.json")
    }

    public static func repoRoot() -> URL {
        // .../spikes/s1/Sources/S1Support/Support.swift -> repo root is 5 levels up
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { u.deleteLastPathComponent() }
        return u
    }

    public static func load() throws -> [String: Any] {
        let data = try Data(contentsOf: url())
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw S1Error.bad("vectors") }
        return o
    }

    public static func suite2(_ v: [String: Any]) throws -> [String: Any] {
        guard let s = (v["suites"] as? [String: Any])?["2"] as? [String: Any] else { throw S1Error.bad("suite 2") }
        return s
    }
}

// MARK: P-256 constants and key import

public let p256N: [UInt8] = Array(try! Data(hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))

func cmp(_ a: [UInt8], _ b: [UInt8]) -> Int {
    for (x, y) in zip(a, b) where x != y { return x < y ? -1 : 1 }
    return 0
}

func sub(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
    var out = a, borrow = 0
    for i in stride(from: a.count - 1, through: 0, by: -1) {
        var d = Int(a[i]) - Int(b[i]) - borrow
        borrow = d < 0 ? 1 : 0
        if d < 0 { d += 256 }
        out[i] = UInt8(d)
    }
    return out
}

func addOne(_ a: [UInt8]) -> [UInt8] {
    var out = a
    for i in stride(from: a.count - 1, through: 0, by: -1) {
        if out[i] == 255 { out[i] = 0 } else { out[i] += 1; break }
    }
    return out
}

/// The vector file's `seed` is NOT the raw private scalar. The reference derives
/// `d = int(seed) mod (n-1) + 1` (ref/orch_protocol_ref.py SuiteP._priv). CryptoKit needs d as 32 raw bytes.
public func scalar(fromSeed seed: Data) -> Data {
    var s = Array(seed)
    let nMinus1 = sub(p256N, [UInt8](repeating: 0, count: 31) + [1])
    while cmp(s, nMinus1) >= 0 { s = sub(s, nMinus1) }   // seed < 2^256 < 2(n-1): at most one pass
    return Data(addOne(s))
}

public func kxKey(seed: Data) throws -> P256.KeyAgreement.PrivateKey {
    try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar(fromSeed: seed))
}

public func sigKey(seed: Data) throws -> P256.Signing.PrivateKey {
    try P256.Signing.PrivateKey(rawRepresentation: scalar(fromSeed: seed))
}

// MARK: protocol functions (docs/protocol-v2.md section 3 and 5)

public func ctx(_ label: String, _ fields: [String]) -> Data {
    Data(([label] + fields).joined(separator: "|").utf8)
}

/// RFC 5869 HKDF-SHA-256. An empty salt is HashLen zero bytes, which is also what CryptoKit does.
public func hkdf(ikm: Data, salt: Data, info: Data, length: Int = 32) -> Data {
    let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: length)
    return k.withUnsafeBytes { Data($0) }
}

/// Raw ECDH output. CryptoKit's SharedSecret exposes the x-coordinate (32 bytes) through withUnsafeBytes.
public func rawBytes(_ ss: SharedSecret) -> Data { ss.withUnsafeBytes { Data($0) } }

public func u32(_ i: Int) -> Data { Data([UInt8(i >> 24 & 255), UInt8(i >> 16 & 255), UInt8(i >> 8 & 255), UInt8(i & 255)]) }

public struct Labels {
    public let kdfSeal: String
    public let aadSeal: String
    public init(_ v: [String: Any]) throws {
        guard let l = v["labels"] as? [String: String], let a = l["kdf_seal"], let b = l["aad_seal"] else { throw S1Error.bad("labels") }
        kdfSeal = a; aadSeal = b
    }
}

public func sealAAD(_ labels: Labels, purpose: String, objectID: Data, epoch: Int, extra: Data = Data()) -> Data {
    let p = Data(purpose.utf8)
    return Data(labels.aadSeal.utf8) + Data([2, UInt8(p.count)]) + p + objectID + u32(epoch) + extra
}

public func sealKey(_ labels: Labels, sharedSecret: Data, ephPub: Data, rcptPub: Data, purpose: String, rcptID: Data) -> SymmetricKey {
    SymmetricKey(data: hkdf(ikm: sharedSecret, salt: ephPub + rcptPub, info: ctx(labels.kdfSeal, [purpose, rcptID.hex])))
}

let zeroNonce = try! AES.GCM.Nonce(data: Data(count: 12))

/// ct||tag, zero nonce (the key is unique per seal because the ephemeral key is).
public func gcmSeal(key: SymmetricKey, plaintext: Data, aad: Data) throws -> Data {
    let box = try AES.GCM.seal(plaintext, using: key, nonce: zeroNonce, authenticating: aad)
    return box.ciphertext + box.tag
}

public func gcmOpen(key: SymmetricKey, blob: Data, aad: Data) throws -> Data {
    guard blob.count >= 16 else { throw S1Error.bad("short") }
    let ct = blob.prefix(blob.count - 16), tag = blob.suffix(16)
    return try AES.GCM.open(AES.GCM.SealedBox(nonce: zeroNonce, ciphertext: ct, tag: tag), using: key, authenticating: aad)
}

/// Production seal (protocol section 5.3): a fresh software ephemeral key is generated here for every call, used once
/// and discarded. The ephemeral key is deliberately NOT a parameter: the zero nonce is safe only because K is unique per
/// seal, and a long-lived key (including a Secure Enclave key) as `eph` would reuse key and nonce.
public func sealTo(_ labels: Labels, rcptPub: Data, rcptID: Data, purpose: String,
                   objectID: Data, epoch: Int, plaintext: Data, extra: Data = Data()) throws -> Data {
    try _sealToWithEphemeralForVectors(labels, eph: P256.KeyAgreement.PrivateKey(), rcptPub: rcptPub, rcptID: rcptID,
                                       purpose: purpose, objectID: objectID, epoch: epoch, plaintext: plaintext, extra: extra)
}

/// TEST-ONLY seam, same as ref.seal_to with a given `eph`: reproduces the vector seals (fixed eph_seed) and lets the
/// fixture tool push a Secure Enclave ECDH output through Python's open_sealed. Never call it from product code.
public func _sealToWithEphemeralForVectors<K: KeyAgreementKey>(_ labels: Labels, eph: K, rcptPub: Data, rcptID: Data, purpose: String,
                                       objectID: Data, epoch: Int, plaintext: Data, extra: Data = Data()) throws -> Data {
    let peer = try P256.KeyAgreement.PublicKey(x963Representation: rcptPub)
    let ephPub = eph.x963
    let ss = rawBytes(try eph.agree(with: peer))
    let k = sealKey(labels, sharedSecret: ss, ephPub: ephPub, rcptPub: rcptPub, purpose: purpose, rcptID: rcptID)
    return ephPub + (try gcmSeal(key: k, plaintext: plaintext, aad: sealAAD(labels, purpose: purpose, objectID: objectID, epoch: epoch, extra: extra)))
}

public func openSealed<K: KeyAgreementKey>(_ labels: Labels, rcpt: K, rcptID: Data, purpose: String, objectID: Data,
                                           epoch: Int, blob: Data, extra: Data = Data()) throws -> Data {
    guard blob.count >= 65 + 16 else { throw S1Error.bad("short") }
    let ephPub = blob.prefix(65), ct = blob.dropFirst(65)
    let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephPub)
    let ss = rawBytes(try rcpt.agree(with: peer))
    let k = sealKey(labels, sharedSecret: ss, ephPub: Data(ephPub), rcptPub: rcpt.x963, purpose: purpose, rcptID: rcptID)
    return try gcmOpen(key: k, blob: Data(ct), aad: sealAAD(labels, purpose: purpose, objectID: objectID, epoch: epoch, extra: extra))
}

/// Abstracts software and Secure Enclave key-agreement keys.
public protocol KeyAgreementKey {
    var x963: Data { get }
    func agree(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: KeyAgreementKey {
    public var x963: Data { publicKey.x963Representation }
    public func agree(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret { try sharedSecretFromKeyAgreement(with: peer) }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: KeyAgreementKey {
    public var x963: Data { publicKey.x963Representation }
    public func agree(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret { try sharedSecretFromKeyAgreement(with: peer) }
}

// MARK: ECDSA signature forms

/// Protocol form: 64 bytes r||s. CryptoKit's `rawRepresentation` is exactly that.
public func rawSig(_ s: P256.Signing.ECDSASignature) -> Data { s.rawRepresentation }

// MARK: strict verification (what the app does before calling CryptoKit)

/// Spec section 1.2 suite 2: 64-byte signature, 1 <= r,s <= n-1, 65-byte `04` public key on the curve; then CryptoKit.
/// CryptoKit alone only throws for some of these (it parses r = 0 or s >= n and relies on isValidSignature).
public func strictVerify(pub: Data, sig: Data, msg: Data) -> Bool {
    guard sig.count == 64 else { return false }
    let r = Array(sig.prefix(32)), s = Array(sig.suffix(32)), zero = [UInt8](repeating: 0, count: 32)
    for x in [r, s] where cmp(x, zero) == 0 || cmp(x, p256N) >= 0 { return false }
    guard pub.count == 65, pub[0] == 4,
          let key = try? P256.Signing.PublicKey(x963Representation: pub),
          let sg = try? P256.Signing.ECDSASignature(rawRepresentation: sig) else { return false }
    return key.isValidSignature(sg, for: msg)
}

/// half of n, for classifying s as high (s > (n-1)/2) or low.
public func isHighS(_ rawSig: Data) -> Bool {
    var half = p256N, carry: UInt8 = 0
    for i in 0..<half.count { let b = half[i]; half[i] = (b >> 1) | carry; carry = (b & 1) << 7 }
    return cmp(Array(rawSig.suffix(32)), half) > 0
}
