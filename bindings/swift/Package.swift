// swift-tools-version:5.7
// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

import PackageDescription

let package = Package(
    name: "PQCDyber",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "PQCDyber",
            targets: ["PQCDyber"]
        ),
    ],
    targets: [
        .systemLibrary(
            name: "Cpqc",
            pkgConfig: "libpqc",
            providers: [
                .brew(["libpqc-dyber"]),
                .apt(["libpqc-dev"]),
            ]
        ),
        .target(
            name: "PQCDyber",
            dependencies: ["Cpqc"],
            path: "Sources/PQCDyber"
        ),
        .testTarget(
            name: "PQCDyberTests",
            dependencies: ["PQCDyber"]
        ),
    ]
)
