import XCTest
@testable import PushCore

/// Runs every `push.cases` vector of suite 2 in tests/vectors_v2.json against PushOpener.
final class VectorTests: XCTestCase {
    static func vectors() throws -> [String: Any] {
        // walk up from this file until tests/vectors_v2.json exists
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        var searched: [String] = []
        for _ in 0..<12 {
            let f = dir.appendingPathComponent("tests/vectors_v2.json")
            searched.append(f.path)
            if FileManager.default.fileExists(atPath: f.path) {
                return try JSONSerialization.jsonObject(with: Data(contentsOf: f)) as! [String: Any]
            }
            dir.deleteLastPathComponent()
        }
        XCTFail("tests/vectors_v2.json not found; searched: \(searched.joined(separator: ", "))")
        throw CocoaError(.fileNoSuchFile)
    }

    static func keys(_ j: [String: Any]) -> [String: PushOpener.WorkspaceKeys] {
        var out: [String: PushOpener.WorkspaceKeys] = [:]
        for (ws, v) in j {
            let e = v as! [String: Any]
            var wk: [Int: Data] = [:]
            for (ep, h) in e["wk"] as! [String: String] { wk[Int(ep)!] = Hex.decode(h, length: 32)! }
            out[ws] = .init(wskPub: B64U.decode(e["wsk_pub"] as! String)!, wsHex: ws, wk: wk)
        }
        return out
    }

    func testAllSuite2PushCases() throws {
        let v = try Self.vectors()
        let s2 = ((v["suites"] as! [String: Any])["2"] as! [String: Any])["push"] as! [String: Any]
        let cases = s2["cases"] as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(cases.count, 11)
        for c in cases {
            let name = c["name"] as! String
            let keys = Self.keys(c["keys"] as! [String: Any])
            var last: [String: Int64] = [:]
            for st in c["steps"] as! [[String: Any]] {
                let exp = st["expect"] as! [String: Any]
                let got = PushOpener.open(raw: Data((st["raw"] as! String).utf8), keys: keys, last: &last,
                                          nowMs: (st["now_ms"] as! NSNumber).int64Value)
                switch got {
                case .drop(let why):
                    XCTAssertEqual(exp["result"] as? String, "drop", name)
                    XCTAssertEqual(exp["why"] as? String, why, name)
                case .show(let p):
                    XCTAssertEqual(exp["result"] as? String, "show", name)
                    XCTAssertEqual(exp["id"] as? String, p.id, name)
                    XCTAssertEqual(exp["kind"] as? String, p.kind, name)
                    XCTAssertEqual(exp["label"] as? String, p.label, name)
                    XCTAssertEqual((exp["ts_ms"] as? NSNumber)?.int64Value, p.tsMs, name)
                }
            }
        }
    }

    func testSignVectors() throws {
        let v = try Self.vectors()
        let sign = ((v["suites"] as! [String: Any])["2"] as! [String: Any])["sign"] as! [[String: Any]]
        for c in sign {
            let pub = Data(hexString: c["pub"] as! String)
            let msg = Data(hexString: c["msg"] as! String)
            let sig = Data(hexString: c["sig"] as! String)
            XCTAssertEqual(PushOpener.verifyP256(pub: pub, sig: sig, msg: msg), c["valid"] as! Bool, c["name"] as! String)
        }
        XCTAssertTrue(sign.contains { ($0["name"] as! String) == "high_s_twin_verifies" })
    }

    func testBOMIsKeptNotDropped() throws {
        let bytes = Data([0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0xEF, 0xBB, 0xBF, 0x78, 0x22, 0x7D])   // {"a":"<BOM>x"}
        let v = try StrictJSON.parse(bytes)
        XCTAssertEqual(v.object?["a"]?.string?.unicodeScalars.count, 2)
        XCTAssertEqual(canonicalJSON(v), bytes)
        XCTAssertThrowsError(try StrictJSON.parse(Data([0x22, 0xFF, 0x22])))      // invalid UTF-8 still refused
    }

    func testLastKeyIsByUTF8BytesNotStringEquality() {
        let a = "\u{e9}", b = "e\u{301}"
        XCTAssertEqual(a, b)                                                      // Swift: equal
        XCTAssertNotEqual(PushOpener.lastKey(wsHex: "00", id: a), PushOpener.lastKey(wsHex: "00", id: b))
    }

    func testStrictJSONRejects() {
        for bad in ["{\"a\":1,\"a\":2}", "{\"a\":1.0}", "{\"a\":1e3}", "{\"é\":1}", "[NaN]", "{\"a\":9007199254740992}", "{\"a\":\"\\ud800\"}", "{} x"] {
            XCTAssertThrowsError(try StrictJSON.parse(Data(bad.utf8)), bad)
        }
    }
}

extension Data {
    init(hexString h: String) {
        let u = Array(h.utf8)
        self = Data(stride(from: 0, to: u.count, by: 2).map { UInt8(String(decoding: u[$0..<$0 + 2], as: UTF8.self), radix: 16)! })
    }
}
