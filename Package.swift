// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SSLCertFetcher",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(name: "certfetcher", targets: ["SSLCertFetcher"]),
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "SSLCertFetcher",
            dependencies: []
        )
    ]
)
