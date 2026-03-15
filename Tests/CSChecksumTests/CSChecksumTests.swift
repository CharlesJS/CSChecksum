import Foundation
import Testing
import System

@testable import CSChecksum

struct Fixture: CustomTestStringConvertible, CustomTestArgumentEncodable, Sendable {
    enum DataChecksumAlgorithm {
        case md2
        case md5
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
    }

    let url: URL
    let intChecksums: [CSChecksumAlgorithm : (UInt, Int)]
    let dataChecksums: [CSChecksumAlgorithm : Data]

    var testDescription: String { url.lastPathComponent }
    func encodeTestArgument(to encoder: some Encoder) throws { try self.url.encode(to: encoder) }

    init(
        name: String,
        intChecksums: [CSChecksumAlgorithm: (UInt, Int)],
        dataChecksums: [DataChecksumAlgorithm: String]
    ) {
        self.url = Bundle.module.url(forResource: name, withExtension: "", subdirectory: "fixtures")!

        self.intChecksums = intChecksums
        var mergedDataChecksums = intChecksums.mapValues { Self.convertChecksumInt($0.0, $0.1) }

#if Crypto
        for (type, cksumString) in dataChecksums {
            let cksumData = Self.convertChecksumString(cksumString)
            switch type {
            case .md5: mergedDataChecksums[.md5] = cksumData
            case .sha1: mergedDataChecksums[.sha1] = cksumData
            case .sha256: mergedDataChecksums[.sha256] = cksumData
            case .sha512: mergedDataChecksums[.sha512] = cksumData
#if canImport(CommonCrypto)
            case .md2: mergedDataChecksums[.md2] = cksumData
            case .sha224: mergedDataChecksums[.sha224] = cksumData
            case .sha384: mergedDataChecksums[.sha384] = cksumData
#endif
            }
        }
#endif

        self.dataChecksums = mergedDataChecksums
    }

    private static func convertChecksumString(_ cksumString: String) -> Data {
        var iterator = cksumString.makeIterator()
        var data = Data()

        while let hi = iterator.next(), let lo = iterator.next() {
            data.append(UInt8("\(hi)\(lo)", radix: 16)!)
        }

        return data
    }

    private static func convertChecksumInt<I: FixedWidthInteger>(_ cksum: I, _ length: Int) -> Data {
        var i = cksum

        return withUnsafeBytes(of: &i) { Data($0.prefix(length)) }
    }
}

let fixtures: [Fixture] = [
    Fixture(
        name: "gettysburg.txt",
        intChecksums: [
            .adler32: (0xa6f11300, 4),
            .crc32: (0x2eb43d19, 4),
            .crc32c: (0x11e42979, 4),
            .posix: (0x5ec96f92, 4)
        ],
        dataChecksums: [
            .md2: "a9095080724e5beffc35ed027f0d84a7",
            .md5: "f7cf20533efd90326ee656e72e22801d",
            .sha1: "1ad822f01126b638ba4c3ca56df32f2087d84b90",
            .sha224: "27240785a8f5911147d5b2e73c3760b828185a7f6b74c7a9c3b5b987",
            .sha256: "463d2aa337dd761d9d634e82b19df72084a162a65511a488d8bacf7cbeb455f9",
            .sha384: "1b98237747fce47f94d2a0c69f8090775d5475471e7ec2c9c024318fc7062361ace122fda22ca7da3e98a051ea7c9118",
            .sha512: "4728caf36f2776d8192123d4650a8af19c44430b317140d7224609c6c58f3ba2f7749f716c1c7b93fb67cc52264d55dd" +
                "854e34f47acf1d207966dd82965275f0"
        ]
    ),
    Fixture(
        name: "test.mp4",
        intChecksums: [
            .adler32: (0x15d66bec, 4),
            .crc32: (0xc3a867a9, 4),
            .crc32c: (0x31182ee1, 4),
            .posix: (0xf63439f7, 4)
        ],
        dataChecksums: [
            .md2: "6e67e0fdb7f7e66b8a7bff24978c2e2e",
            .md5: "ca971677116da0b83e22485bb5ae840f",
            .sha1: "1623262fb1f52c1b844cbe3b6e8f3caf830ff4f5",
            .sha224: "eefcc05380a3d28ef30e6ea1aacbadb78e93602837aef1b1b0a23c6f",
            .sha256: "9f08a180929681536a0d0ab59fba8454fed8c1d10f3cda17f4ad04793d7583a7",
            .sha384: "f078a1cad9a3be1d8da82bf12e7229611a26b13721c39a1df277d789288e037b01f07d8dde8b412ef9d816c8d81ecc9b",
            .sha512: "61e6863b59c3bce19d0187401ca0ec58a527bc5e147f0864cb8001b520b57e0e7ad57f5801c46d28b445cdb7d0768582" +
                "f7b921315997655125d8a65444d26add"
        ]
    ),
    Fixture(
        name: "hello.png",
        intChecksums: [
            .adler32: (0xb719d50c, 4),
            .crc32: (0xcf8bf108, 4),
            .crc32c: (0x46b46c53, 4),
            .posix: (0xc3a0ef52, 4)
        ],
        dataChecksums: [
            .md2: "a9b1d6ecfc5b29fc70249b3c25138514",
            .md5: "fe08257dd19c051f6466fb5ecd8936be",
            .sha1: "d25f664243e3e78736ef94db9bd890e969aa42e5",
            .sha224: "0c1f63615fa1af4c79d8a33051f6bc81a84cbee6f09396d021327566",
            .sha256: "86d943916bd63acfa04390897d763b2390b2bfb9ba206036cb87cb275fd1153c",
            .sha384: "5576ca254a79a5655fb47196b159245d37af2fa807e4d1a676c4e577b0727ef33a80d4b89a1d328d7f7eed7008c17957",
            .sha512: "362fa03bdd36ca1890da39be8e71e4a07f97aa0105df91e241548d1dbd7b00ab63b5cede22d8c35ca821bacb85438a95" +
                "382cf98ababa137d49317c1edaf31f6b"
        ]
    ),
    Fixture(
        name: "block0",
        intChecksums: [
            .adler32: (0x613b0e39, 4),
            .crc32: (0x57e9754e, 4),
            .crc32c: (0x8fea43e4, 4),
            .fletcher64(withCheckBytes: true): (0x12a43341c1dba050, 8),
            .fletcher64(withCheckBytes: false): (0x12a433412b802c6e, 8),
            .posix: (0x4edc3f86, 4),
        ],
        dataChecksums: [:]
    )
]

@Test(arguments: fixtures)
func testIntChecksums(fixture: Fixture) throws {
    let url = fixture.url

    var adler32 = CSChecksum.adler32()
    var crc32 = CSChecksum.crc32()
    var crc32c = CSChecksum.crc32c()
    var fletch64Check = CSChecksum.fletcher64(withCheckBytes: true)
    var posix = CSChecksum.posix()

    let handle = try FileHandle(forReadingFrom: url)
    defer { _ = try? handle.close() }

    while let chunk = try handle.read(upToCount: 1024), !chunk.isEmpty {
        adler32.update(withInputData: chunk)
        crc32.update(withInputData: chunk)
        crc32c.update(withInputData: chunk)
        fletch64Check.update(withInputData: chunk)
        posix.update(withInputData: chunk)
    }

    // updating with an empty data should have no effect on the result
    adler32.update(withInputData: Data())
    crc32.update(withInputData: Data())
    crc32c.update(withInputData: Data())
    fletch64Check.update(withInputData: Data())
    posix.update(withInputData: Data())

    let checksums: [CSChecksumAlgorithm: (UInt, Int)] = [
        .adler32: (UInt(adler32.finalize()), 4),
        .crc32: (UInt(crc32.finalize()), 4),
        .crc32c: (UInt(crc32c.finalize()), 4),
        .fletcher64(withCheckBytes: true): (UInt(fletch64Check.finalize()), 8),
        .posix: (UInt(posix.finalize()), 4),
    ]

    for (algorithm, checksum) in checksums {
        if let expected = fixture.intChecksums[algorithm] {
            if checksum != expected {
                print("failure for \(algorithm)")
            }

            #expect(
                checksum == expected,
                "\(algorithm.description): expected \(String(expected.0, radix: 16)), got \(String(checksum.0, radix: 16))"
            )
        }
    }
}

@Test(arguments: fixtures)
func testDataChecksums(fixture: Fixture) throws {
    let url = fixture.url
    let data = try Data(contentsOf: url)

    var adler32 = CSChecksum(algorithm: .adler32)
    var crc32 = CSChecksum(algorithm: .crc32)
    var crc32c = CSChecksum(algorithm: .crc32c)
    var posix = CSChecksum(algorithm: .posix)
#if Crypto
    var md5 = CSChecksum(algorithm: .md5)
    var sha1 = CSChecksum(algorithm: .sha1)
    var sha256 = CSChecksum.sha256()
    var sha512 = CSChecksum.sha512()
#if canImport(CommonCrypto)
    var md2 = CSChecksum(algorithm: .md2)
    var sha224 = CSChecksum.sha224()
    var sha384 = CSChecksum.sha384()
#endif
#endif

    let handle = try FileHandle(forReadingFrom: url)
    defer { _ = try? handle.close() }

    while let chunk = try handle.read(upToCount: 1024), !chunk.isEmpty {
        adler32.update(withInputData: chunk)
        crc32.update(withInputData: chunk)
        crc32c.update(withInputData: chunk)
        posix.update(withInputData: chunk)
#if Crypto
        md5.update(withInputData: chunk)
        sha1.update(withInputData: chunk)
        sha256.update(withInputData: chunk)
        sha512.update(withInputData: chunk)
#if canImport(CommonCrypto)
        md2.update(withInputData: chunk)
        sha224.update(withInputData: chunk)
        sha384.update(withInputData: chunk)
#endif
#endif
    }

    // updating with an empty data should have no effect on the result
    adler32.update(withInputData: Data())
    crc32.update(withInputData: Data())
    crc32c.update(withInputData: Data())
    posix.update(withInputData: Data())
#if Crypto
    md5.update(withInputData: Data())
    sha1.update(withInputData: Data())
    sha256.update(withInputData: Data())
    sha512.update(withInputData: Data())
#if canImport(CommonCrypto)
    md2.update(withInputData: Data())
    sha224.update(withInputData: Data())
    sha384.update(withInputData: Data())
#endif
#endif

#if Crypto
#if canImport(CommonCrypto)
    let ccChecksums: [CSChecksumAlgorithm: Data] = [
        .md2: Data(md2.finalize()),
        .sha224: Data(sha224.finalize()),
        .sha384: Data(sha384.finalize()),
    ]
#else
    let ccChecksums: [CSChecksumAlgorithm: Data] = [:]
#endif

    let cryptoChecksums: [CSChecksumAlgorithm: Data] = [
        .md5: Data(md5.finalize()),
        .sha1: Data(sha1.finalize()),
        .sha256: Data(sha256.finalize()),
        .sha512: Data(sha512.finalize())
    ].merging(ccChecksums) { $1 }
#else
    let cryptoChecksums: [CSChecksumAlgorithm: Data] = [:]
#endif

    let checksums: [CSChecksumAlgorithm: Data] = [
        .adler32: Data(adler32.finalize()),
        .crc32: Data(crc32.finalize()),
        .crc32c: Data(crc32c.finalize()),
        .posix: Data(posix.finalize()),
    ].merging(cryptoChecksums) { $1 }

    for (algorithm, checksumData) in checksums {
        if let expected = fixture.dataChecksums[algorithm] {
            if checksumData != expected {
                print("failure for \(algorithm)")
            }
            
            #expect(checksumData == expected)
            #expect(Data(CSChecksum.checksum(for: data, algorithm: algorithm)) == expected)
            #expect(Data(try CSChecksum.checksum(at: FilePath(url.path), algorithm: algorithm)) == expected)
#if Foundation
            #expect(Data(try CSChecksum.checksum(at: url, algorithm: algorithm)) == expected)
#endif
        }
    }
}

@available(macOS 12.0, *)
@Test(arguments: fixtures)
func testAsyncDataChecksums(fixture: Fixture) async throws {
    let url = fixture.url

    let handle = try FileHandle(forReadingFrom: url)
    defer { _ = try? handle.close() }

    for (algorithm, expected) in fixture.dataChecksums {
        let bufSizes = [1024, 10, 1023, 10240]

        for eachBufSize in bufSizes {
            try handle.seek(toOffset: 0)
            let checksum = try await CSChecksum.checksum(
                for: handle.bytes,
                algorithm: algorithm,
                bufferSize: eachBufSize
            )

            func checksumString(_ data: some Collection<UInt8>) -> String {
                data.map { String(format: "%02x", $0) }.joined()
            }

            #expect(
                Data(checksum) == expected,
                "\(algorithm.description): expected \(checksumString(expected)), got \(checksumString(checksum))"
            )
        }
    }
}

@Test(arguments: fixtures)
func testUnaligned(fixture: Fixture) throws {
    let url = fixture.url

    var adler32 = CSChecksum(algorithm: .adler32)
    var crc32 = CSChecksum(algorithm: .crc32)
    var crc32c = CSChecksum(algorithm: .crc32c)
    var fletcherWithCheckBytes = CSChecksum(algorithm: .fletcher64(withCheckBytes: true))
    var fletcherWithoutCheckBytes = CSChecksum(algorithm: .fletcher64(withCheckBytes: false))
    var posix = CSChecksum(algorithm: .posix)

#if Crypto
    var md5 = CSChecksum(algorithm: .md5)
    var sha1 = CSChecksum(algorithm: .sha1)
    var sha256 = CSChecksum.sha256()
    var sha512 = CSChecksum.sha512()
#if canImport(CommonCrypto)
    var md2 = CSChecksum(algorithm: .md2)
    var sha224 = CSChecksum.sha224()
    var sha384 = CSChecksum.sha384()
#endif
#endif

    let handle = try FileHandle(forReadingFrom: url)
    defer { _ = try? handle.close() }

    let largerBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 1025, alignment: 1)
    defer { largerBuffer.deallocate() }

    let buffer = UnsafeMutableRawBufferPointer(rebasing: largerBuffer.dropFirst())

    while let chunk = try handle.read(upToCount: 1024), !chunk.isEmpty {
        buffer.copyBytes(from: chunk)

        let chunkBuffer = UnsafeRawBufferPointer(rebasing: buffer.prefix(chunk.count))

        adler32.update(withInputData: chunkBuffer)
        crc32.update(withInputData: chunkBuffer)
        crc32c.update(withInputData: chunkBuffer)
        fletcherWithCheckBytes.update(withInputData: chunkBuffer)
        fletcherWithoutCheckBytes.update(withInputData: chunkBuffer)
        posix.update(withInputData: chunkBuffer)
#if Crypto
        md5.update(withInputData: chunkBuffer)
        sha1.update(withInputData: chunkBuffer)
        sha256.update(withInputData: chunkBuffer)
        sha512.update(withInputData: chunkBuffer)
#if canImport(CommonCrypto)
        md2.update(withInputData: chunkBuffer)
        sha224.update(withInputData: chunkBuffer)
        sha384.update(withInputData: chunkBuffer)
#endif
#endif
    }

    // updating with an empty data should have no effect on the result
    adler32.update(withInputData: Data())
    crc32.update(withInputData: Data())
    crc32c.update(withInputData: Data())
    fletcherWithCheckBytes.update(withInputData: Data())
    fletcherWithoutCheckBytes.update(withInputData: Data())
    posix.update(withInputData: Data())
#if Crypto
    md5.update(withInputData: Data())
    sha1.update(withInputData: Data())
    sha256.update(withInputData: Data())
    sha512.update(withInputData: Data())
#if canImport(CommonCrypto)
    md2.update(withInputData: Data())
    sha224.update(withInputData: Data())
    sha384.update(withInputData: Data())
#endif
#endif

#if Crypto
#if canImport(CommonCrypto)
    let ccChecksums: [CSChecksumAlgorithm: Data] = [
        .md2: Data(md2.finalize()),
        .sha224: Data(sha224.finalize()),
        .sha384: Data(sha384.finalize()),
    ]
#else
    let ccChecksums: [CSChecksumAlgorithm: Data] = [:]
#endif

    let cryptoChecksums: [CSChecksumAlgorithm: Data] = [
        .md5: Data(md5.finalize()),
        .sha1: Data(sha1.finalize()),
        .sha256: Data(sha256.finalize()),
        .sha512: Data(sha512.finalize())
    ].merging(ccChecksums) { $1 }
#else
    let cryptoChecksums: [CSChecksumAlgorithm: Data] = [:]
#endif

    let checksums: [CSChecksumAlgorithm: Data] = [
        .adler32: Data(adler32.finalize()),
        .crc32: Data(crc32.finalize()),
        .crc32c: Data(crc32c.finalize()),
        .fletcher64(withCheckBytes: true): Data(fletcherWithCheckBytes.finalize()),
        .fletcher64(withCheckBytes: false): Data(fletcherWithoutCheckBytes.finalize()),
        .posix: Data(posix.finalize()),
    ].merging(cryptoChecksums) { $1 }

    for (algorithm, checksumData) in checksums {
        if let expected = fixture.dataChecksums[algorithm] {
            if checksumData != expected {
                print("failure for \(algorithm)")
            }

            #expect(checksumData == expected)
        }
    }
}

let excessivelyLongData: Data = {
    let repeated = "yes it goes on and on my friends".data(using: .ascii)!

    return (0..<134217728).reduce(into: Data()) { data, _ in
        data += repeated
    }
}()

let excessivelyLongDataResults: [CSChecksumAlgorithm: Data] = {
    var results: [CSChecksumAlgorithm: Data] = [.crc32: Data([0x56, 0x28, 0xe3, 0xe5])]

#if Crypto
    results[.sha224] = Data([
        0xef, 0x7c, 0xa8, 0x6d, 0x5e, 0x86, 0x6c, 0xbc, 0xf7, 0xfe, 0x1e, 0x0d, 0xa1, 0xf4, 0x0c, 0x89,
        0x0d, 0xaf, 0x72, 0x59, 0x0c, 0x8f, 0x17, 0x0c, 0x7c, 0xec, 0x6b, 0x76
    ])

    results[.sha512] = Data([
        0x2f, 0x76, 0xf7, 0xd0, 0x56, 0x1d, 0xe2, 0x48, 0x58, 0xfe, 0x5b, 0xa6, 0xc4, 0xda, 0x72, 0xfa,
        0x4c, 0xac, 0xc1, 0x8e, 0x35, 0xa7, 0x81, 0xf4, 0xeb, 0xe2, 0xfa, 0xe6, 0x48, 0xef, 0xfe, 0x01,
        0x72, 0x17, 0x74, 0x1d, 0xa3, 0x33, 0xb5, 0x5b, 0x31, 0x83, 0xf0, 0xfe, 0x74, 0xda, 0xe5, 0xb9,
        0xa8, 0xe8, 0x88, 0xaa, 0x84, 0x43, 0xa5, 0x7e, 0xb6, 0x2e, 0x3a, 0x94, 0x97, 0xa7, 0xf4, 0xcd
    ])
#endif

    return results
}()

@Test(arguments: excessivelyLongDataResults)
func testExcessivelyLongInputData(algorithm: CSChecksumAlgorithm, expected: Data) {
    #expect(Data(CSChecksum.checksum(for: excessivelyLongData, algorithm: algorithm)) == expected)
}

@Test
func testAlgorithmNames() {
    #expect(CSChecksumAlgorithm.adler32.description == "Adler32")
    #expect(CSChecksumAlgorithm.crc32.description == "CRC32")
#if Crypto
    #expect(CSChecksumAlgorithm.md5.description == "MD5")
    #expect(CSChecksumAlgorithm.sha1.description == "SHA1")
    #expect(CSChecksumAlgorithm.sha256.description == "SHA256")
    #expect(CSChecksumAlgorithm.sha512.description == "SHA512")
#if canImport(CommonCrypto)
    #expect(CSChecksumAlgorithm.md2.description == "MD2")
    #expect(CSChecksumAlgorithm.sha224.description == "SHA224")
    #expect(CSChecksumAlgorithm.sha384.description == "SHA384")
#endif
#endif
}
