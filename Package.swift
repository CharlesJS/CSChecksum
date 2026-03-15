// swift-tools-version: 6.1

import PackageDescription

#if arch(x86_64)
let swiftSettings: [PackageDescription.SwiftSetting]? = [
    .unsafeFlags([
        "-Xcc", "-Xclang", "-Xcc", "-target-feature", "-Xcc", "-Xclang", "-Xcc", "+sse4.2",
        "-Xcc", "-Xclang", "-Xcc", "-target-feature", "-Xcc", "-Xclang", "-Xcc", "+pclmul",
    ])
]
#else
let swiftSettings: [PackageDescription.SwiftSetting]? = nil
#endif

let package = Package(
    name: "CSChecksum",
    platforms: [
        .macOS(.v10_15),
        .macCatalyst(.v13),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "CSChecksum",
            targets: ["CSChecksum"]
        )
    ],
    traits: [
        "Crypto",
        "Foundation",
        "ZLib"
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "5.0.0"),
        .package(url: "https://github.com/CharlesJS/SyncPolyfill", from: "0.1.1"),
    ],
    targets: [
        .target(
            name: "asm"
        ),
        .target(
            name: "CSChecksum",
            dependencies: [
                "asm",
                "SyncPolyfill",
                .product(name: "Crypto", package: "swift-crypto", condition: .when(traits: ["Crypto"]))
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CSChecksumTests",
            dependencies: ["CSChecksum"],
            resources: [
                .copy("fixtures")
            ]
        ),
    ]
)
