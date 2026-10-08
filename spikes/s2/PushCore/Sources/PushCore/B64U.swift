import Foundation

public enum B64U {
    /// Canonical unpadded base64url only (protocol-v2 section 2.2). Returns nil on any deviation.
    public static func decode(_ s: String, length: Int? = nil) -> Data? {
        let u = Array(s.utf8)
        guard u.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F }),
              u.count % 4 != 1 else { return nil }
        var std = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        std += String(repeating: "=", count: (4 - std.count % 4) % 4)
        guard let d = Data(base64Encoded: std), encode(d) == s else { return nil }   // rejects non-zero trailing bits
        if let n = length, d.count != n { return nil }
        return d
    }

    public static func encode(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public enum Hex {
    /// Lower-case hex of an exact byte length.
    public static func decode(_ s: String, length: Int) -> Data? {
        let u = Array(s.utf8)
        guard u.count == 2 * length else { return nil }
        var out = Data()
        func nib(_ c: UInt8) -> UInt8? { c >= 0x30 && c <= 0x39 ? c - 0x30 : (c >= 0x61 && c <= 0x66 ? c - 0x61 + 10 : nil) }
        for k in stride(from: 0, to: u.count, by: 2) {
            guard let h = nib(u[k]), let l = nib(u[k + 1]) else { return nil }
            out.append(h << 4 | l)
        }
        return out
    }
    public static func encode(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
}
