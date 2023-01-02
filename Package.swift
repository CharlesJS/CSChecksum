// swift-tools-version: 5.7

import PackageDescription

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
        .package(url: "https://github.com/CharlesJS/CSDataProtocol", from: "0.1.0")
    ],
    targets: [
        .target(
            name: "CSChecksum",
            dependencies: ["CSDataProtocol"]
        ),
        .target(
            name: "CSChecksum_Foundation",
            dependencies: [
                "CSChecksum",
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
