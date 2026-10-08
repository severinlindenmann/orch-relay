// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "S1",
    platforms: [.macOS(.v14), .iOS(.v18)],
    products: [
        .library(name: "S1Support", targets: ["S1Support"]),
        .executable(name: "s1-fixtures", targets: ["s1-fixtures"]),
    ],
    targets: [
        .target(name: "S1Support"),
        .executableTarget(name: "s1-fixtures", dependencies: ["S1Support"]),
        .testTarget(name: "S1Tests", dependencies: ["S1Support"]),
    ],
    swiftLanguageModes: [.v5]
)
