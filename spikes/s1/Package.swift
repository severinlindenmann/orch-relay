// swift-tools-version:6.0
import PackageDescription

// Library + tests only, so that `xcodebuild test -scheme S1` works for the iOS Simulator
// (an executable target in the same package leaves the scheme with no iOS destinations).
// The fixture generator / --presence tool is the sibling package in ./tool.
let package = Package(
    name: "S1",
    platforms: [.macOS(.v14), .iOS(.v18)],
    products: [.library(name: "S1Support", targets: ["S1Support"])],
    targets: [
        .target(name: "S1Support"),
        .testTarget(name: "S1Tests", dependencies: ["S1Support"]),
    ],
    swiftLanguageModes: [.v5]
)
