// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "tauri-plugin-keystore",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "tauri-plugin-keystore",
            type: .static,
            targets: ["tauri-plugin-keystore"]),
    ],
    targets: [
        .target(
            name: "tauri-plugin-keystore",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources/KeystorePlugin"),
        .testTarget(
            name: "KeystorePluginTests",
            dependencies: ["tauri-plugin-keystore"],
            path: "Tests/KeystorePluginTests")
    ]
)
