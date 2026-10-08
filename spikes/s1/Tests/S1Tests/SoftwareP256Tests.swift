import CryptoKit
import XCTest
@testable import S1Support

/// CryptoKit software P-256 against the suite 2 vectors in tests/vectors_v2.json.
final class SoftwareP256Tests: XCTestCase {
    var v: [String: Any] = [:]
    var s2: [String: Any] = [:]
    var labels: Labels!

    override func setUpWithError() throws {
        v = try Vectors.load()
        s2 = try Vectors.suite2(v)
        labels = try Labels(v)
    }

    func hex(_ o: Any?) throws -> Data { try Data(hex: (o as? String) ?? "") }

    func testSeedToScalarMatchesVectorPubs() throws {
        let keys = s2["keys"] as! [String: [String: String]]
        XCTAssertGreaterThan(keys.count, 10)
        for (name, k) in keys {
            let seed = try Data(hex: k["seed"]!), pub = try Data(hex: k["pub"]!)
            let got: Data = name.hasSuffix(".kx") ? try kxKey(seed: seed).publicKey.x963Representation
                                                  : try sigKey(seed: seed).publicKey.x963Representation
            XCTAssertEqual(got.count, 65, name)
            XCTAssertEqual(got[0], 4, name)
            XCTAssertEqual(got, pub, name)
        }
    }

    /// Verify as the app would: any throw (bad point, bad length) counts as "reject".
    func ckVerify(pub: Data, sig: Data, msg: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: pub),
              let s = try? P256.Signing.ECDSASignature(rawRepresentation: sig) else { return false }
        return key.isValidSignature(s, for: msg)   // hashes msg with SHA-256 internally
    }

    func testSignVectorsAgreeWithCryptoKit() throws {
        for c in s2["sign"] as! [[String: Any]] {
            let name = c["name"] as! String
            let got = ckVerify(pub: try hex(c["pub"]), sig: try hex(c["sig"]), msg: try hex(c["msg"]))
            XCTAssertEqual(got, c["valid"] as! Bool, "CryptoKit disagrees with vector \(name)")
        }
    }

    /// Records CryptoKit's behaviour for the malleable twin: it ACCEPTS (r, n-s), exactly like the vector says.
    func testHighSTwinIsAcceptedByCryptoKit() throws {
        let cases = s2["sign"] as! [[String: Any]]
        let valid = cases.first { $0["name"] as? String == "valid" }!
        let twin = cases.first { $0["name"] as? String == "high_s_twin_verifies" }!
        let sig = try hex(twin["sig"]), orig = try hex(valid["sig"])
        XCTAssertEqual(sig.prefix(32), orig.prefix(32))                 // same r
        XCTAssertNotEqual(sig.suffix(32), orig.suffix(32))              // different s
        XCTAssertTrue(ckVerify(pub: try hex(twin["pub"]), sig: sig, msg: try hex(twin["msg"])))
        XCTAssertTrue(ckVerify(pub: try hex(valid["pub"]), sig: orig, msg: try hex(valid["msg"])))
    }

    func testSignaturesAreNonDeterministic() throws {
        let k = P256.Signing.PrivateKey()
        let msg = Data("same message".utf8)
        let a = try k.signature(for: msg).rawRepresentation, b = try k.signature(for: msg).rawRepresentation
        XCTAssertEqual(a.count, 64)
        XCTAssertNotEqual(a, b, "CryptoKit ECDSA is randomised: vectors can only check verify, not bytes")
        XCTAssertTrue(k.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: a), for: msg))
    }

    func testDerAndRawRoundTrip() throws {
        let k = P256.Signing.PrivateKey()
        let sig = try k.signature(for: Data("m".utf8))
        let der = sig.derRepresentation
        XCTAssertEqual(der[0], 0x30)
        let again = try P256.Signing.ECDSASignature(derRepresentation: der)
        XCTAssertEqual(again.rawRepresentation, sig.rawRepresentation)
    }

    func testSealVectorsReproduce() throws {
        for c in s2["seal"] as! [[String: Any]] {
            let ephSeed = try hex(c["eph_seed"]), rcptPub = try hex(c["recipient_kx_pub"])
            let rcptID = try hex(c["recipient_id"]), objectID = try hex(c["object_id"])
            let purpose = c["purpose"] as! String, epoch = c["epoch"] as! Int
            let eph = try kxKey(seed: ephSeed)
            XCTAssertEqual(eph.publicKey.x963Representation, try hex(c["eph_pub"]))
            // ECDH: shared secret is the 32-byte x-coordinate
            let ss = rawBytes(try eph.agree(with: P256.KeyAgreement.PublicKey(x963Representation: rcptPub)))
            XCTAssertEqual(ss.count, 32)
            XCTAssertEqual(ss, try hex(c["shared_secret"]))
            // HKDF with salt = eph_pub || rcpt_pub
            let key = sealKey(labels, sharedSecret: ss, ephPub: eph.x963, rcptPub: rcptPub, purpose: purpose, rcptID: rcptID)
            XCTAssertEqual(key.withUnsafeBytes { Data($0) }, try hex(c["key"]))
            let aad = sealAAD(labels, purpose: purpose, objectID: objectID, epoch: epoch, extra: try hex(c["extra_aad"]))
            XCTAssertEqual(aad, try hex(c["aad"]))
            // AES-GCM is deterministic with the zero nonce: whole blob must match
            let sealed = try sealTo(labels, eph: eph, rcptPub: rcptPub, rcptID: rcptID, purpose: purpose, objectID: objectID,
                                    epoch: epoch, plaintext: try hex(c["plaintext"]), extra: try hex(c["extra_aad"]))
            XCTAssertEqual(sealed, try hex(c["sealed"]))
        }
    }

    func testEcdhFromBothSidesAgree() throws {
        let keys = s2["keys"] as! [String: [String: String]]
        let a = try kxKey(seed: try Data(hex: keys["phone.kx"]!["seed"]!))
        let b = try kxKey(seed: try Data(hex: keys["laptop.kx"]!["seed"]!))
        XCTAssertEqual(rawBytes(try a.agree(with: b.publicKey)), rawBytes(try b.agree(with: a.publicKey)))
    }

    func testHkdfVectors() throws {
        let cases = s2["hkdf"] as! [[String: Any]]
        XCTAssertGreaterThan(cases.count, 5)
        for c in cases {
            let info = try hex(c["info"])
            XCTAssertEqual(String(decoding: info, as: UTF8.self), c["info_text"] as? String)
            let okm = hkdf(ikm: try hex(c["ikm"]), salt: try hex(c["salt"]), info: info)
            XCTAssertEqual(okm, try hex(c["okm"]), c["name"] as! String)
        }
        // empty salt == 32 zero bytes in CryptoKit
        let ikm = Data(repeating: 7, count: 32), info = Data("x".utf8)
        XCTAssertEqual(hkdf(ikm: ikm, salt: Data(), info: info), hkdf(ikm: ikm, salt: Data(count: 32), info: info))
    }

    func testSaltedAeadVectors() throws {
        for c in s2["salted_aead"] as! [[String: Any]] {
            let kBase = try hex(c["k_base"]), blob = try hex(c["sealed"])
            let salt = blob.prefix(16)
            let kMsg = hkdf(ikm: kBase, salt: Data(salt), info: Data((c["msg_label"] as! String).utf8))
            XCTAssertEqual(kMsg, try hex(c["k_msg"]))
            let pt = try gcmOpen(key: SymmetricKey(data: kMsg), blob: Data(blob.dropFirst(16)), aad: try hex(c["aad"]))
            XCTAssertEqual(pt, try hex(c["plaintext"]))
        }
    }

    func testSealOpenVectors() throws {
        let keys = s2["keys"] as! [String: [String: String]]
        for c in s2["seal_open"] as! [[String: Any]] {
            let who = c["recipient"] as! String
            let priv = try kxKey(seed: try Data(hex: keys["\(who).kx"]!["seed"]!))
            let r = try? openSealed(labels, rcpt: priv, rcptID: try hex(c["recipient_id"]), purpose: c["purpose"] as! String,
                                    objectID: try hex(c["object_id"]), epoch: c["epoch"] as! Int, blob: try hex(c["sealed"]))
            if let expect = c["plaintext"] as? String {
                XCTAssertEqual(r, try Data(hex: expect), c["name"] as! String)
            } else {
                XCTAssertNil(r, "must fail: \(c["name"] as! String)")
            }
        }
    }

    func testOffCurvePublicKeyRejectedByCryptoKit() throws {
        let cases = s2["sign"] as! [[String: Any]]
        let bad = try hex(cases.first { $0["name"] as? String == "point_not_on_curve" }!["pub"])
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(x963Representation: bad))
        XCTAssertThrowsError(try P256.Signing.PublicKey(x963Representation: bad))
        // compressed and short encodings are not accepted as x963
        XCTAssertThrowsError(try P256.Signing.PublicKey(x963Representation: Data(bad.prefix(33))))
    }

    func testSoftwareKeyIsExportable() {
        let k = P256.KeyAgreement.PrivateKey()
        XCTAssertEqual(k.rawRepresentation.count, 32)
    }
}
