// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KeystorePlugin",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(name: "KeystorePlugin", targets: ["KeystorePlugin"])
    ],
    targets: [
        .target(name: "KeystorePlugin", path: "Sources/KeystorePlugin"),
        .testTarget(name: "KeystorePluginTests", dependencies: ["KeystorePlugin"], path: "Tests/KeystorePluginTests")
    ]
)
