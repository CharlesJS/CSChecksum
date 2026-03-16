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

#if arch(arm64) && !canImport(Darwin)
let cSettings: [PackageDescription.CSetting]? = [.unsafeFlags(["-march=armv8-a+crc+crypto+sha3"])]
#elseif arch(x86_64) && !canImport(Darwin)
let cSettings: [PackageDescription.CSetting]? = [.unsafeFlags(["-msse4.2", "-mpclmul"])]
#else
let cSettings: [PackageDescription.CSetting]? = nil
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
        .package(url: "https://github.com/apple/swift-system", from: "1.6.1"),
    ],
    targets: [
        .target(
            name: "asm",
            cSettings: cSettings
        ),
        .target(
            name: "CSChecksum",
            dependencies: [
                "asm",
                .product(name: "SyncPolyfill", package: "SyncPolyfill"),
                .product(name: "Crypto", package: "swift-crypto", condition: .when(traits: ["Crypto"])),
                .product(name: "SystemPackage", package: "swift-system", condition: .when(platforms: [.linux]))
            ],
            cSettings: cSettings,
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
