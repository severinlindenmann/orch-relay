// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PushCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "PushCore", targets: ["PushCore"])],
    targets: [
        .target(name: "PushCore"),
        .testTarget(name: "PushCoreTests", dependencies: ["PushCore"]),
    ]
)
