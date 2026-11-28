//
//  CSChecksum.swift
//
//  Created by Charles Srstka on 4/3/14.
//  Copyright © 2014-2026 Charles Srstka. All rights reserved.
//

#if canImport(Darwin)
import System
#else
import SystemPackage
#endif

#if Crypto
import Crypto

#if canImport(CommonCrypto)
import CommonCrypto
#endif
#endif

#if Foundation
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

#if ZLib && canImport(zlib)
import zlib
#endif

package let defaultBufsize = 1024 * 10

public struct CSChecksum<Raw: RawValue>: ~Copyable {
    private enum Backing {
        case adler32(UInt32)
        case bsd(BSDCksumState)
        case fletcher64(lo: UInt64, hi: UInt64, byteBuffer: ContiguousArray<UInt8>)
        case fusionCRC32(UInt32)
        case fusionCRC32C(UInt32)
        case tabularCRC32(UInt32, [UInt32])
        case data(ContiguousArray<UInt8>)
        case rawPointer(UnsafeMutableRawPointer, _ finalize: (UnsafeMutableRawPointer) -> ContiguousArray<UInt8>)
#if Crypto
        case crypto(any HashFunction)
#if canImport(CommonCrypto)
        case sha224(UnsafeMutablePointer<CC_SHA256_CTX>)
        case sha384(UnsafeMutablePointer<CC_SHA512_CTX>)
#endif
#endif
#if ZLib && canImport(zlib)
        case zlib(uLong)
#endif
    }

    private struct AsyncDataChunkSequence<Base: AsyncSequence>: AsyncSequence where Base.Element == UInt8 {
        typealias Element = ContiguousArray<UInt8>

        let base: Base
        let bufferSize: Int

        struct AsyncIterator: AsyncIteratorProtocol {
            @usableFromInline var iterator: Base.AsyncIterator
            @usableFromInline var accumulator: ContiguousArray<UInt8> = []
            @usableFromInline let bufferSize: Int

            @inlinable @inline(__always)
            public mutating func next() async rethrows -> Element? {
                while let byte = try await self.iterator.next() {
                    self.accumulator.append(byte)

                    if self.accumulator.count >= self.bufferSize {
                        defer { self.accumulator.removeAll() }
                        return self.accumulator
                    }
                }

                if !self.accumulator.isEmpty {
                    defer { self.accumulator.removeAll() }
                    return self.accumulator
                }

                return nil
            }
        }

        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(iterator: self.base.makeAsyncIterator(), bufferSize: self.bufferSize)
        }
    }

    private var algorithm: CSChecksumAlgorithm
    private var backing: Backing

    public static func checksum(
        for data: some Collection<UInt8>,
        algorithm: CSChecksumAlgorithm
    ) -> some Collection<UInt8> where Raw == ContiguousArray<UInt8> {
        var cksum = CSChecksum(algorithm: algorithm)

        cksum.update(withInputData: data)

        return cksum.finalize()
    }

    public static func checksum<S: AsyncSequence>(
        for data: S,
        algorithm: CSChecksumAlgorithm,
        bufferSize: Int? = nil
    ) async throws -> some Collection<UInt8> where S.Element == UInt8, Raw == ContiguousArray<UInt8> {
        try await self.checksum(
            for: AsyncDataChunkSequence(base: data, bufferSize: bufferSize ?? defaultBufsize),
            algorithm: algorithm
        )
    }

    public static func checksum<S: AsyncSequence>(
        for data: S,
        algorithm: CSChecksumAlgorithm
    ) async throws -> some Collection<UInt8> where S.Element: Collection<UInt8>, Raw == ContiguousArray<UInt8> {
        var cksum = CSChecksum(algorithm: algorithm)

        for try await eachChunk in data {
            cksum.update(withInputData: eachChunk)
        }

        return cksum.finalize()
    }

    @available(macOS 11.0, macCatalyst 14.0, iOS 14.0, tvOS 14.0, watchOS 7.0, *)
    public static func checksum(
        at path: FilePath,
        algorithm: CSChecksumAlgorithm
    ) throws -> some Collection<UInt8> where Raw == ContiguousArray<UInt8> {
        let desc = try FileDescriptor.open(path, .readOnly)
        defer { _ = try? desc.close() }

        var cksum = CSChecksum(algorithm: algorithm)

        let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: defaultBufsize, alignment: 1)
        defer { buf.deallocate() }

        while case let bytesRead = try desc.read(into: buf), bytesRead != 0 {
            cksum.update(withInputData: UnsafeRawBufferPointer(buf).prefix(bytesRead))
        }

        return cksum.finalize()
    }

#if Foundation
    @available(macOS 10.15.4, macCatalyst 13.4, iOS 13.4, tvOS 13.4, watchOS 6.2, *)
    public static func checksum(
        at url: URL,
        algorithm: CSChecksumAlgorithm
    ) throws -> some Collection<UInt8> where Raw == ContiguousArray<UInt8> {
#if canImport(FoundationEssentials)
        try self.checksum(at: FilePath(url.path), algorithm: algorithm)
#else
        let handle = try FileHandle(forReadingFrom: url)
        defer { _ = try? handle.close() }

        var cksum = CSChecksum(algorithm: algorithm)

        while let data = try autoreleasepool(invoking: { try handle.read(upToCount: defaultBufsize) }), !data.isEmpty {
            cksum.update(withInputData: data)
        }

        return cksum.finalize()
#endif
    }
#endif

    public static func adler32() -> Self where Raw == UInt32 { .init(algorithm: .adler32, returnType: UInt32.self) }
    public static func posix() -> Self where Raw == UInt32 { .init(algorithm: .posix, returnType: UInt32.self) }
    public static func crc32() -> Self where Raw == UInt32 { .init(algorithm: .crc32, returnType: UInt32.self) }
    public static func crc32c() -> Self where Raw == UInt32 { .init(algorithm: .crc32c, returnType: UInt32.self) }
    public static func fletcher64(withCheckBytes: Bool = true) -> Self where Raw == UInt64 {
        .init(algorithm: .fletcher64(withCheckBytes: withCheckBytes), returnType: UInt64.self)
    }

#if Crypto
    public static func sha256() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha256) }
    public static func sha512() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha512) }
#if canImport(CommonCrypto)
    public static func sha224() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha224) }
    public static func sha384() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha384) }
#endif
#endif

    public init(algorithm: CSChecksumAlgorithm) where Raw == ContiguousArray<UInt8> {
        self.init(algorithm: algorithm, returnType: ContiguousArray<UInt8>.self)
    }

    private init(algorithm: CSChecksumAlgorithm, returnType: Raw.Type) {
        self.algorithm = algorithm

        switch algorithm {
        case .adler32:
#if ZLib && canImport(zlib)
            self.backing = .zlib(zlib.adler32(0, nil, 0))
#else
            self.backing = .adler32(1)
#endif
        case .crc32:
            self.backing = if supportsFusionCRC32 {
                .fusionCRC32(0)
            } else {
#if ZLib && canImport(zlib)
                .zlib(zlib.crc32(0, nil, 0))
#else
                .tabularCRC32(0, TabularCRC32.getCRC32Table(poly: TabularCRC32.crc32ReversePoly))
#endif
            }
        case .crc32c:
            self.backing = if supportsFusionCRC32C {
                .fusionCRC32C(0)
            } else {
                .tabularCRC32(0, TabularCRC32.getCRC32Table(poly: TabularCRC32.crc32CReversePoly))
            }
        case .fletcher64:
            self.backing = .fletcher64(lo: 0, hi: 0, byteBuffer: [])
        case .posix:
            self.backing = .bsd(BSDCksumState())
#if Crypto
        case .md5:
            self.backing = .crypto(Insecure.MD5())
        case .sha1:
            self.backing = .crypto(Insecure.SHA1())
        case .sha256:
            self.backing = .crypto(SHA256())
        case .sha512:
            self.backing = .crypto(SHA512())
#if canImport(CommonCrypto)
        case .md2:
            self.backing = .rawPointer(deprecatedStuff.md2Init(), deprecatedStuff.md2Finalize)
        case .sha224:
            let ctx = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
            CC_SHA224_Init(ctx)
            self.backing = .sha224(ctx)
        case .sha384:
            let ctx = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
            CC_SHA384_Init(ctx)
            self.backing = .sha384(ctx)
#endif
#endif
        }
    }

    deinit {
        switch self.backing {
        case .adler32, .data, .bsd, .fletcher64, .fusionCRC32, .fusionCRC32C, .tabularCRC32:
            break
#if ZLib && canImport(zlib)
        case .zlib:
            break
#endif
        case let .rawPointer(ptr, finalize):
            _ = finalize(ptr)
            ptr.deallocate()
#if Crypto
        case .crypto:
            break
#if canImport(CommonCrypto)
        case let .sha224(ptr):
            ptr.deallocate()
        case let .sha384(ptr):
            ptr.deallocate()
#endif
#endif
        }
    }

#if Foundation
    public mutating func update(withInputData data: some DataProtocol) {
        for eachRegion in data.regions {
            eachRegion.withUnsafeBytes {
                self.update(withBytes: $0)
            }
        }
    }
#endif

    public mutating func update(withInputData data: some Collection<UInt8>) {
        if data.withContiguousStorageIfAvailable({ self.update(withBytes: UnsafeRawBufferPointer($0)) }) == nil {
            withUnsafeTemporaryAllocation(byteCount: data.count, alignment: 1) {
                let bytes = $0.initializeMemory(as: UInt8.self, fromContentsOf: data)
                self.update(withBytes: UnsafeRawBufferPointer(bytes))
            }
        }
    }

    private mutating func update(withBytes bytes: UnsafeRawBufferPointer) {
        if bytes.isEmpty { return }

        let maxLength = switch self.algorithm {
        case .adler32, .crc32, .crc32c:
            Int(Int32.max)
        case .fletcher64, .posix:
            Int.max
#if Crypto
        case .md5, .sha1, .sha256, .sha512:
            Int.max
#if canImport(CommonCrypto)
        case .md2, .sha224, .sha384:
            Int(CC_LONG.max)
#endif
#endif
        }

        if bytes.count > maxLength {
            let cutoff = bytes.index(bytes.startIndex, offsetBy: maxLength)

            self.update(withBytes: .init(rebasing: bytes[..<cutoff]))
            self.update(withBytes: .init(rebasing: bytes[cutoff...]))

            return
        }

        guard let ptr = bytes.baseAddress else { return }

        switch (self.algorithm, self.backing) {
        case (.adler32, .adler32(let cksum)):
            self.backing = .adler32(Fletcher.adler32(bytes: bytes, initialValue: cksum))
#if ZLib && canImport(zlib)
        case (.adler32, .zlib(let cksum)):
            self.backing = .zlib(zlib.adler32(cksum, ptr, uInt(bytes.count)))
        case (.crc32, .zlib(let cksum)):
            self.backing = .zlib(zlib.crc32(cksum, ptr, uInt(bytes.count)))
#endif
        case (.posix, .bsd(let state)):
            state.update(data: bytes)
#if arch(arm64)
        case (.crc32, .fusionCRC32(let cksum)):
            self.backing = .fusionCRC32(FusionCRC32.crc32(bytes: bytes, initialValue: cksum))
#endif
        case (.crc32c, .fusionCRC32C(let cksum)):
            self.backing = .fusionCRC32C(FusionCRC32C.crc32c(bytes: bytes, initialValue: cksum))
        case (.crc32, .tabularCRC32(let cksum, let table)):
            let newCksum = TabularCRC32.calculateCRC32(bytes, initialValue: cksum, table: table)
            self.backing = .tabularCRC32(newCksum, table)
        case (.crc32c, .tabularCRC32(let cksum, let table)):
            let newCksum = TabularCRC32.calculateCRC32(bytes, initialValue: cksum, table: table)
            self.backing = .tabularCRC32(newCksum, table)
        case (.fletcher64, .fletcher64(lo: var lo, hi: var hi, byteBuffer: var byteBuffer)):
            let rem = bytes.count % 4

            if _fastPath(rem == 0 && byteBuffer.isEmpty) {
                (lo, hi) = Fletcher.fletcher64(bytes: bytes, lowSum: lo, highSum: hi)
            } else if byteBuffer.isEmpty {
                (lowSum: lo, highSum: hi) = Fletcher.fletcher64(bytes: bytes, lowSum: lo, highSum: hi)

                byteBuffer.replaceSubrange(byteBuffer.indices, with: bytes.suffix(rem))
            } else {
                (byteBuffer + bytes).withUnsafeBytes { newBytes in
                    (lowSum: lo, highSum: hi) = Fletcher.fletcher64(bytes: newBytes, lowSum: lo, highSum: hi)

                    let newRem = newBytes.count % 4
                    byteBuffer.replaceSubrange(byteBuffer.indices, with: newBytes.suffix(newRem))
                }
            }

            self.backing = .fletcher64(lo: lo, hi: hi, byteBuffer: byteBuffer)
#if Crypto
        case (_, .crypto(let _hashFunction)):
            var hashFunction = _hashFunction
            hashFunction.update(data: bytes)
            self.backing = .crypto(hashFunction)
#if canImport(CommonCrypto)
        case (.md2, .rawPointer(let ctx, _)):
            deprecatedStuff.md2Update(ctx: ctx, ptr: ptr, count: bytes.count)
        case (.sha224, .sha224(let ctx)):
            CC_SHA224_Update(ctx, ptr, CC_LONG(bytes.count))
        case (.sha384, .sha384(let ctx)):
            CC_SHA384_Update(ctx, ptr, CC_LONG(bytes.count))
#endif
#endif
        default:
            fatalError("Invalid combination of algorithm \(self.algorithm) and backing \(self.backing)")
        }
    }

    public mutating func finalize() -> Raw {
        func makeData(count: Int, closure: (UnsafeMutablePointer<UInt8>) -> ()) -> ContiguousArray<UInt8> {
            .init(unsafeUninitializedCapacity: count) { ptr, outCount in
                closure(ptr.baseAddress!)
                outCount = count
            }
        }

        switch self.backing {
        case .adler32(let cksum):
            return Raw(checksumInteger: cksum)
        case .fletcher64(lo: let lo, hi: let hi, byteBuffer: _):
            let cksum: UInt64
            if case .fletcher64(let withCheckBytes) = self.algorithm, withCheckBytes {
                cksum = Fletcher.fletcher64Finalize(lowSum: lo, highSum: hi, includeCheckBytes: true)
            } else {
                cksum = Fletcher.fletcher64Finalize(lowSum: lo, highSum: hi, includeCheckBytes: false)
            }

            return Raw(checksumInteger: cksum)
        case .fusionCRC32(let cksum):
            return Raw(checksumInteger: cksum)
        case .fusionCRC32C(let cksum):
            return Raw(checksumInteger: cksum)
        case .tabularCRC32(let cksum, _):
            return Raw(checksumInteger: cksum)
#if ZLib && canImport(zlib)
        case let .zlib(cksum):
            return Raw(checksumInteger: UInt32(cksum))
#endif
        case let .bsd(state):
            return Raw(checksumInteger: state.crc)
        case let .rawPointer(ctx, finalize):
            let data = finalize(ctx)
            self.backing = .data(data)
            return Raw(checksumBytes: data)
#if Crypto
        case .crypto(let hashFunction):
            return Raw(checksumBytes: ContiguousArray(hashFunction.finalize()))
#if canImport(CommonCrypto)
        case let .sha224(ctx):
            let data = makeData(count: Int(CC_SHA224_DIGEST_LENGTH)) { _ = CC_SHA224_Final($0, ctx) }

            ctx.deallocate()
            self.backing = .data(data)

            return Raw(checksumBytes: data)
        case let .sha384(ctx):
            let data = makeData(count: Int(CC_SHA384_DIGEST_LENGTH)) { _ = CC_SHA384_Final($0, ctx) }

            ctx.deallocate()
            self.backing = .data(data)

            return Raw(checksumBytes: data)
#endif
#endif
        case let .data(data):
            return Raw(checksumBytes: data)
        }
    }
}
