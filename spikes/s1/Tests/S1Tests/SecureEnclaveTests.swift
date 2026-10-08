import CryptoKit
import Security
import XCTest
@testable import S1Support

/// Secure Enclave keys. Skipped where SecureEnclave.isAvailable is false (Simulator, Intel Macs without T2).
final class SecureEnclaveTests: XCTestCase {
    var v: [String: Any] = [:]
    var s2: [String: Any] = [:]
    var labels: Labels!

    override func setUpWithError() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("SecureEnclave.isAvailable == false on this destination: Secure Enclave tests skipped")
        }
        v = try Vectors.load()
        s2 = try Vectors.suite2(v)
        labels = try Labels(v)
    }

    /// `.privateKeyUsage` only: no biometry / passcode, so automation can use the key.
    /// Accessibility: WhenUnlockedThisDeviceOnly (the class to use for a key that must not work while the device is
    /// locked). It needs an unlocked screen: with the screen locked, key creation fails with -25308 (AKSError
    /// -536870174, kIOReturnNotPermitted); that case is turned into a skip with a clear message.
    /// Do NOT copy AfterFirstUnlock* for signing keys: it lets the key sign while the device is locked.
    func ac() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &err) else {
            throw err!.takeRetainedValue() as Error
        }
        return ac
    }

    func make<T>(_ f: () throws -> T) throws -> T {
        do { return try f() } catch let e as NSError where e.domain == NSOSStatusErrorDomain && e.code == -25308 {
            throw XCTSkip("Secure Enclave key creation refused (-25308): the device/screen is locked. Unlock it and rerun.")
        }
    }
    func sigKey() throws -> SecureEnclave.P256.Signing.PrivateKey { try make { try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac()) } }
    func kxKeySE() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey { try make { try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac()) } }

    func vectorKx(_ name: String) throws -> P256.KeyAgreement.PrivateKey {
        let keys = s2["keys"] as! [String: [String: String]]
        return try kxKey(seed: try Data(hex: keys[name]!["seed"]!))
    }

    func testSigningKeyPublicFormatAndSignature() throws {
        let k = try sigKey()
        let pub = k.publicKey.x963Representation
        XCTAssertEqual(pub.count, 65)
        XCTAssertEqual(pub[0], 4)
        XCTAssertNoThrow(try P256.Signing.PublicKey(x963Representation: pub))
        let msg = Data("orch v2 signature vector".utf8)
        let sig = try k.signature(for: msg)
        XCTAssertEqual(sig.rawRepresentation.count, 64)                 // raw r||s, protocol form
        XCTAssertTrue(k.publicKey.isValidSignature(sig, for: msg))
        let sig2 = try k.signature(for: msg)
        XCTAssertNotEqual(sig.rawRepresentation, sig2.rawRepresentation, "SE ECDSA is randomised")
        XCTAssertTrue(k.publicKey.isValidSignature(sig2, for: msg))
        // protocol-style verification of a raw signature with a software key rebuilt from the x963 pub
        let soft = try P256.Signing.PublicKey(x963Representation: pub)
        XCTAssertTrue(soft.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: sig.rawRepresentation), for: msg))
        XCTAssertFalse(soft.isValidSignature(sig, for: Data("other".utf8)))
    }

    func testKeyAgreementKeyFormat() throws {
        let k = try kxKeySE()
        XCTAssertEqual(k.publicKey.x963Representation.count, 65)
        XCTAssertEqual(k.publicKey.x963Representation[0], 4)
    }

    /// SE ECDH vs a vector software key: both sides must produce the same 32-byte x-coordinate.
    func testEcdhWithVectorKeyAgrees() throws {
        let se = try kxKeySE()
        let vec = try vectorKx("phone.kx")
        let a = rawBytes(try se.agree(with: vec.publicKey))
        let b = rawBytes(try vec.agree(with: try P256.KeyAgreement.PublicKey(x963Representation: se.publicKey.x963Representation)))
        XCTAssertEqual(a.count, 32)
        XCTAssertEqual(a, b)
    }

    /// Software sealer -> SE recipient, and SE ephemeral -> software recipient, both round-trip.
    func testSealToAndFromSecureEnclave() throws {
        let se = try kxKeySE()
        let soft = P256.KeyAgreement.PrivateKey()
        let rid = try Data(hex: "4177b27d8e4ac182e8d388b247d2b136"), oid = try Data(hex: "705d40abbb8c1c90354a1acaa94c935c")
        let pt = Data("wk-bytes".utf8)
        // soft eph -> SE recipient
        let b1 = try sealTo(labels, rcptPub: se.x963, rcptID: rid, purpose: "wk", objectID: oid, epoch: 1, plaintext: pt)
        XCTAssertEqual(try openSealed(labels, rcpt: se, rcptID: rid, purpose: "wk", objectID: oid, epoch: 1, blob: b1), pt)
        XCTAssertThrowsError(try openSealed(labels, rcpt: se, rcptID: rid, purpose: "sk", objectID: oid, epoch: 1, blob: b1))
        // SE eph -> soft recipient
        let b2 = try _sealToWithEphemeralForVectors(labels, eph: se, rcptPub: soft.x963, rcptID: rid, purpose: "wk", objectID: oid, epoch: 1, plaintext: pt)
        XCTAssertEqual(try openSealed(labels, rcpt: soft, rcptID: rid, purpose: "wk", objectID: oid, epoch: 1, blob: b2), pt)
    }

    func testDataRepresentationReload() throws {
        let k = try sigKey()
        let blob = k.dataRepresentation
        XCTAssertGreaterThan(blob.count, 65)
        XCTAssertNotEqual(blob.count, 32, "this is a wrapped handle, not the 32-byte scalar")
        let again = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        XCTAssertEqual(again.publicKey.x963Representation, k.publicKey.x963Representation)
        let msg = Data("reload".utf8)
        XCTAssertTrue(k.publicKey.isValidSignature(try again.signature(for: msg), for: msg))

        let ka = try kxKeySE()
        let ka2 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: ka.dataRepresentation)
        XCTAssertEqual(ka.publicKey.x963Representation, ka2.publicKey.x963Representation)
        let vec = try vectorKx("laptop.kx")
        XCTAssertEqual(rawBytes(try ka.agree(with: vec.publicKey)), rawBytes(try ka2.agree(with: vec.publicKey)))
    }

    func testPrivateKeyIsNotExportable() throws {
        let k = try sigKey()
        // dataRepresentation is a device-bound handle, not key material; the software types refuse it.
        // (These throw on length alone; they document the type boundary, they do not prove the blob hides the scalar.)
        XCTAssertThrowsError(try P256.Signing.PrivateKey(rawRepresentation: k.dataRepresentation))
        XCTAssertThrowsError(try P256.Signing.PrivateKey(x963Representation: k.dataRepresentation))
        // Non-exportability itself is the API surface (no raw/x963/PEM/DER export exists on SecureEnclave.P256.*).
    }

    func testSecureEnclaveRejectsGarbageDataRepresentation() {
        XCTAssertThrowsError(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(repeating: 1, count: 80)))
    }
}
