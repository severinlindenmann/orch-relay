// swift-tools-version:6.0
import PackageDescription

// `swift run s1-fixtures` (writes ../fixtures/se-mac.json) and `swift run s1-fixtures --presence` (manual).
let package = Package(
    name: "S1Tool",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "..")],
    targets: [
        .executableTarget(name: "s1-fixtures", dependencies: [.product(name: "S1Support", package: "S1")]),
    ],
    swiftLanguageModes: [.v5]
)
