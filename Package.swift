// swift-tools-version: 6.0

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
        ),
        .library(
            name: "CSChecksum+Foundation",
            targets: ["CSChecksum_Foundation"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/CharlesJS/CSDataProtocol", from: "0.1.0"),
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
                "CSDataProtocol",
                "SyncPolyfill"
            ],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "CSChecksum_Foundation",
            dependencies: [
                "CSChecksum",
                "asm",
                .product(name: "CSDataProtocol+Foundation", package: "CSDataProtocol")
            ]
        ),
        .testTarget(
            name: "CSChecksumTests",
            dependencies: ["CSChecksum_Foundation"],
            resources: [
                .copy("fixtures")
            ]
        ),
    ]
)
