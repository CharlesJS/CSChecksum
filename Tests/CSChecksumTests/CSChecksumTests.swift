import XCTest
import System
@testable import CSChecksum
@testable import CSChecksum_Foundation

final class CSChecksumTests: XCTestCase {
    private static let bundle = Bundle(for: CSChecksumTests.self)

    private struct Fixture {
        private static let bundle: Bundle = {
            let bundleURL = CSChecksumTests.bundle.url(forResource: "CSChecksum_CSChecksumTests", withExtension: "bundle")!

            return Bundle(url: bundleURL)!
        }()

        let url: URL
        let checksums: [CSChecksum.Algorithm : Data]

        init(name: String, checksums: [CSChecksum.Algorithm: String]) {
            self.url = Self.bundle.url(forResource: name, withExtension: "", subdirectory: "fixtures")!
            self.checksums = checksums.mapValues { Self.convertChecksumString($0) }
        }

        private static func convertChecksumString(_ cksumString: String) -> Data {
            var iterator = cksumString.makeIterator()
            var data = Data()

            while let hi = iterator.next(), let lo = iterator.next() {
                data.append(UInt8("\(hi)\(lo)", radix: 16)!)
            }

            return data
        }
    }

    private static let fixtures: [Fixture] = [
        Fixture(
            name: "gettysburg.txt",
            checksums: [
                .adler32: "0013f1a6",
                .crc32: "193db42e",
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
            checksums: [
                .adler32: "ec6bd615",
                .crc32: "a967a8c3",
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
            checksums: [
                .adler32: "0cd519b7",
                .crc32: "08f18bcf",
                .md2: "a9b1d6ecfc5b29fc70249b3c25138514",
                .md5: "fe08257dd19c051f6466fb5ecd8936be",
                .sha1: "d25f664243e3e78736ef94db9bd890e969aa42e5",
                .sha224: "0c1f63615fa1af4c79d8a33051f6bc81a84cbee6f09396d021327566",
                .sha256: "86d943916bd63acfa04390897d763b2390b2bfb9ba206036cb87cb275fd1153c",
                .sha384: "5576ca254a79a5655fb47196b159245d37af2fa807e4d1a676c4e577b0727ef33a80d4b89a1d328d7f7eed7008c17957",
                .sha512: "362fa03bdd36ca1890da39be8e71e4a07f97aa0105df91e241548d1dbd7b00ab63b5cede22d8c35ca821bacb85438a95" +
                    "382cf98ababa137d49317c1edaf31f6b"
            ]
        )
    ]

    func testChecksums() throws {
        for eachFixture in Self.fixtures {
            let url = eachFixture.url
            let data = try Data(contentsOf: url)

            let checksums = Dictionary(uniqueKeysWithValues: eachFixture.checksums.keys.map {
                ($0, CSChecksum(algorithm: $0))
            })

            let handle = try FileHandle(forReadingFrom: url)
            defer { _ = try? handle.close() }

            while let chunk = try handle.read(upToCount: 1024), !chunk.isEmpty {
                for eachChecksum in checksums.values {
                    eachChecksum.update(withInputData: chunk)
                }
            }

            // updating with an empty data should have no effect on the result
            checksums.values.first?.update(withInputData: Data())

            for (algorithm, checksum) in checksums {
                let expected = eachFixture.checksums[algorithm]

                XCTAssertEqual(Data(checksum.checksumData), expected)
                XCTAssertEqual(Data(checksum.checksumData), expected) // make sure it returns the same value when rerun
                XCTAssertEqual(Data(CSChecksum.checksum(for: data, algorithm: algorithm)), expected)
                XCTAssertEqual(Data(try CSChecksum.checksum(at: FilePath(url.path), algorithm: algorithm)), expected)
                XCTAssertEqual(Data(try CSChecksum.checksum(at: url, algorithm: algorithm)), expected)
            }
        }
    }

    @available(macOS 12.0, *)
    func testAsyncChecksums() async throws {
        for eachFixture in Self.fixtures {
            let url = eachFixture.url

            let handle = try FileHandle(forReadingFrom: url)
            defer { _ = try? handle.close() }

            for (algorithm, expected) in eachFixture.checksums {
                let bufSizes = [1024, 10, 1023, 10240]

                for eachBufSize in bufSizes {
                    try handle.seek(toOffset: 0)
                    let checksum = try await CSChecksum.checksum(
                        for: handle.bytes,
                        algorithm: algorithm,
                        bufferSize: eachBufSize
                    )

                    XCTAssertEqual(Data(checksum), expected)
                }
            }
        }
    }

    func testExcessivelyLongInputData() {
        let repeated = "yes it goes on and on my friends".data(using: .ascii)!

        let data = (0..<134217728).reduce(into: Data()) { data, _ in
            data += repeated
        }

        var expected: UInt32 = 0xe5e32856

        withUnsafeBytes(of: &expected) {
            XCTAssertEqual(Data(CSChecksum.checksum(for: data, algorithm: .crc32)), Data($0))
        }
    }

    func testAlgorithmNames() {
        XCTAssertEqual(CSChecksum.Algorithm.adler32.description, "Adler32")
        XCTAssertEqual(CSChecksum.Algorithm.crc32.description, "CRC32")
        XCTAssertEqual(CSChecksum.Algorithm.md2.description, "MD2")
        XCTAssertEqual(CSChecksum.Algorithm.md5.description, "MD5")
        XCTAssertEqual(CSChecksum.Algorithm.sha1.description, "SHA1")
        XCTAssertEqual(CSChecksum.Algorithm.sha224.description, "SHA224")
        XCTAssertEqual(CSChecksum.Algorithm.sha256.description, "SHA256")
        XCTAssertEqual(CSChecksum.Algorithm.sha384.description, "SHA384")
        XCTAssertEqual(CSChecksum.Algorithm.sha512.description, "SHA512")
    }
}
