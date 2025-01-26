//
//  CSChecksum.swift
//
//  Created by Charles Srstka on 4/3/14.
//  Copyright © 2014-2025 Charles Srstka. All rights reserved.
//

import CommonCrypto
import CSDataProtocol
import System
import zlib

package let defaultBufsize = 1024 * 10

public struct CSChecksum<Raw: RawValue>: ~Copyable {
    private enum Backing {
        case bsd(BSDCksumState)
        case hardwareCRC32C(UInt32)
        case data(ContiguousArray<UInt8>)
        case rawPointer(UnsafeMutableRawPointer, _ finalize: (UnsafeMutableRawPointer) -> ContiguousArray<UInt8>)
        case sha1(UnsafeMutablePointer<CC_SHA1_CTX>)
        case sha256(UnsafeMutablePointer<CC_SHA256_CTX>)
        case sha512(UnsafeMutablePointer<CC_SHA512_CTX>)
        case zlib(uLong)
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
        for data: some DataProtocol,
        algorithm: CSChecksumAlgorithm
    ) -> some DataProtocol where Raw == ContiguousArray<UInt8> {
        var cksum = CSChecksum(algorithm: algorithm)

        cksum.update(withInputData: data)

        return cksum.finalize()
    }

    public static func checksum<S: AsyncSequence>(
        for data: S,
        algorithm: CSChecksumAlgorithm,
        bufferSize: Int? = nil
    ) async throws -> some DataProtocol where S.Element == UInt8, Raw == ContiguousArray<UInt8> {
        try await self.checksum(
            for: AsyncDataChunkSequence(base: data, bufferSize: bufferSize ?? defaultBufsize),
            algorithm: algorithm
        )
    }

    public static func checksum<S: AsyncSequence>(
        for data: S,
        algorithm: CSChecksumAlgorithm
    ) async throws -> some DataProtocol where S.Element: DataProtocol, Raw == ContiguousArray<UInt8> {
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
    ) throws -> some DataProtocol where Raw == ContiguousArray<UInt8> {
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

    public static func adler32() -> Self where Raw == UInt32 { .init(algorithm: .adler32, returnType: UInt32.self) }
    public static func posix() -> Self where Raw == UInt32 { .init(algorithm: .posix, returnType: UInt32.self) }
    public static func crc32() -> Self where Raw == UInt32 { .init(algorithm: .crc32, returnType: UInt32.self) }
    public static func crc32c() -> Self where Raw == UInt32 { .init(algorithm: .crc32c, returnType: UInt32.self) }
    public static func sha224() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha224) }
    public static func sha256() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha256) }
    public static func sha384() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha384) }
    public static func sha512() -> Self where Raw == ContiguousArray<UInt8> { .init(algorithm: .sha512) }

    public init(algorithm: CSChecksumAlgorithm) where Raw == ContiguousArray<UInt8> {
        self.init(algorithm: algorithm, returnType: ContiguousArray<UInt8>.self)
    }

    private init(algorithm: CSChecksumAlgorithm, returnType: Raw.Type) {
        self.algorithm = algorithm

        switch algorithm {
        case .adler32:
            self.backing = .zlib(zlib.adler32(0, nil, 0))
        case .posix:
            self.backing = .bsd(BSDCksumState())
        case .crc32:
            self.backing = .zlib(zlib.crc32(0, nil, 0))
        case.crc32c:
            self.backing = .hardwareCRC32C(0)
        case .md2:
            self.backing = .rawPointer(deprecatedStuff.md2Init(), deprecatedStuff.md2Finalize)
        case .md5:
            self.backing = .rawPointer(deprecatedStuff.md5Init(), deprecatedStuff.md5Finalize)
        case .sha1:
            let ctx = UnsafeMutablePointer<CC_SHA1_CTX>.allocate(capacity: 1)
            CC_SHA1_Init(ctx)
            self.backing = .sha1(ctx)
        case .sha224:
            let ctx = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
            CC_SHA224_Init(ctx)
            self.backing = .sha256(ctx)
        case .sha256:
            let ctx = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
            CC_SHA256_Init(ctx)
            self.backing = .sha256(ctx)
        case .sha384:
            let ctx = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
            CC_SHA384_Init(ctx)
            self.backing = .sha512(ctx)
        case .sha512:
            let ctx = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
            CC_SHA512_Init(ctx)
            self.backing = .sha512(ctx)
        }
    }

    deinit {
        switch self.backing {
        case .zlib, .data, .bsd, .hardwareCRC32C:
            break
        case let .rawPointer(ptr, finalize):
            _ = finalize(ptr)
            ptr.deallocate()
        case let .sha1(ptr):
            ptr.deallocate()
        case let .sha256(ptr):
            ptr.deallocate()
        case let .sha512(ptr):
            ptr.deallocate()
        }
    }

    public mutating func update(withInputData data: some DataProtocol) {
        if data.isEmpty { return }

        let maxLength = switch self.algorithm {
        case .adler32, .crc32, .crc32c:
            Int(Int32.max)
        case .posix:
            Int.max
        case .md2, .md5, .sha1, .sha224, .sha256, .sha384, .sha512:
            Int(CC_LONG.max)
        }

        if data.count > maxLength {
            let cutoff = data.index(data.startIndex, offsetBy: maxLength)

            self.update(withInputData: data[..<cutoff])
            self.update(withInputData: data[cutoff...])

            return
        }

        data.regions.forEach {
            $0.withUnsafeBytes { rawBytes in
                let bytes = rawBytes.bindMemory(to: UInt8.self)
                guard let ptr = bytes.baseAddress else { return }

                switch (self.algorithm, self.backing) {
                case (.adler32, .zlib(let cksum)):
                    self.backing = .zlib(zlib.adler32(cksum, ptr, uInt(bytes.count)))
                case (.posix, .bsd(let state)):
                    state.update(data: bytes)
                case (.crc32, .zlib(let cksum)):
                    self.backing = .zlib(zlib.crc32(cksum, ptr, uInt(bytes.count)))
                case (.crc32c, .hardwareCRC32C(let cksum)):
                    self.backing = .hardwareCRC32C(HardwareCRC32.crc32c(bytes: rawBytes, initialValue: cksum))
                case (.md2, .rawPointer(let ctx, _)):
                    deprecatedStuff.md2Update(ctx: ctx, ptr: ptr, count: bytes.count)
                case (.md5, .rawPointer(let ctx, _)):
                    deprecatedStuff.md5Update(ctx: ctx, ptr: ptr, count: bytes.count)
                case (.sha1, .sha1(let ctx)):
                    CC_SHA1_Update(ctx, ptr, CC_LONG(bytes.count))
                case (.sha224, .sha256(let ctx)):
                    CC_SHA224_Update(ctx, ptr, CC_LONG(bytes.count))
                case (.sha256, .sha256(let ctx)):
                    CC_SHA256_Update(ctx, ptr, CC_LONG(bytes.count))
                case (.sha384, .sha512(let ctx)):
                    CC_SHA384_Update(ctx, ptr, CC_LONG(bytes.count))
                case (.sha512, .sha512(let ctx)):
                    CC_SHA512_Update(ctx, ptr, CC_LONG(bytes.count))
                default:
                    fatalError("Invalid combination of algorithm and backing")
                }
            }
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
        case .hardwareCRC32C(let cksum):
            return Raw(checksumInteger: cksum)
        case let .zlib(cksum):
            return Raw(checksumInteger: UInt32(cksum))
        case let .bsd(state):
            return Raw(checksumInteger: state.crc)
        case let .rawPointer(ctx, finalize):
            let data = finalize(ctx)
            self.backing = .data(data)
            return Raw(checksumBytes: data)
        case let .sha1(ctx):
            let data = makeData(count: Int(CC_SHA1_DIGEST_LENGTH)) { _ = CC_SHA1_Final($0, ctx) }

            ctx.deallocate()
            self.backing = .data(data)

            return Raw(checksumBytes: data)
        case let .sha256(ctx):
            switch self.algorithm {
            case .sha224:
                let data = makeData(count: Int(CC_SHA224_DIGEST_LENGTH)) { _ = CC_SHA224_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return Raw(checksumBytes: data)
            case .sha256:
                let data = makeData(count: Int(CC_SHA256_DIGEST_LENGTH)) { _ = CC_SHA256_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return Raw(checksumBytes: data)
            default:
                fatalError("Illegal backing/algorithm combo")
            }
        case let .sha512(ctx):
            switch self.algorithm {
            case .sha384:
                let data = makeData(count: Int(CC_SHA384_DIGEST_LENGTH)) { _ = CC_SHA384_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return Raw(checksumBytes: data)
            case .sha512:
                let data = makeData(count: Int(CC_SHA512_DIGEST_LENGTH)) { _ = CC_SHA512_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return Raw(checksumBytes: data)
            default:
                fatalError("Illegal backing/algorithm combo")
            }
        case let .data(data):
            return Raw(checksumBytes: data)
        }
    }
}
