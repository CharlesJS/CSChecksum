//
//  CSChecksum.swift
//
//  Created by Charles Srstka on 4/3/14.
//  Copyright © 2014-2022 Charles Srstka. All rights reserved.
//

import System
import zlib
import CommonCrypto
import CSDataProtocol

public class CSChecksum {
    @_spi(CSChecksumInternal) public static let bufsize = 1024 * 10

    public enum Algorithm: UInt8, CustomStringConvertible {
        case crc32
        case adler32
        case md2     // WARNING: Not secure. Included for use in parsing legacy file types only.
        case md5     // WARNING: Not secure. Included for use in parsing legacy file types only.
        case sha1    // WARNING: Not secure. Included for use in parsing legacy file types only.
        case sha224
        case sha256
        case sha384
        case sha512

        public var description: String {
            switch self {
            case .crc32:
                return "CRC32"
            case .adler32:
                return "Adler32"
            case .md2:
                return "MD2"
            case .md5:
                return "MD5"
            case .sha1:
                return "SHA1"
            case .sha224:
                return "SHA224"
            case .sha256:
                return "SHA256"
            case .sha384:
                return "SHA384"
            case .sha512:
                return "SHA512"
            }
        }
    }

    private enum Backing {
        case zlib(uLong)
        case md2(UnsafeMutableRawPointer)
        case md5(UnsafeMutableRawPointer)
        case sha1(UnsafeMutablePointer<CC_SHA1_CTX>)
        case sha256(UnsafeMutablePointer<CC_SHA256_CTX>)
        case sha512(UnsafeMutablePointer<CC_SHA512_CTX>)
        case data(ContiguousArray<UInt8>)
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

    private var algorithm: Algorithm
    private var backing: Backing

    public static func checksum(for data: some DataProtocol, algorithm: Algorithm) -> some DataProtocol {
        let cksum = CSChecksum(algorithm: algorithm)

        cksum.update(withInputData: data)

        return cksum.checksumData
    }

    public static func checksum<S: AsyncSequence>(
        for data: S,
        algorithm: Algorithm,
        bufferSize: Int = 10240
    ) async throws -> some DataProtocol where S.Element == UInt8 {
        try await self.checksum(for: AsyncDataChunkSequence(base: data, bufferSize: bufferSize), algorithm: algorithm)
    }

    public static func checksum<S: AsyncSequence>(
        for data: S,
        algorithm: Algorithm
    ) async throws -> some DataProtocol where S.Element: DataProtocol {
        let cksum = CSChecksum(algorithm: algorithm)

        for try await eachChunk in data {
            cksum.update(withInputData: eachChunk)
        }

        return cksum.checksumData
    }

    @available(macOS 11.0, macCatalyst 14.0, iOS 14.0, tvOS 14.0, watchOS 7.0, *)
    public static func checksum(at path: FilePath, algorithm: Algorithm) throws -> some DataProtocol {
        let desc = try FileDescriptor.open(path, .readOnly)
        defer { _ = try? desc.close() }

        let cksum = CSChecksum(algorithm: algorithm)

        let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: CSChecksum.bufsize, alignment: 1)
        defer { buf.deallocate() }

        while case let bytesRead = try desc.read(into: buf), bytesRead != 0 {
            cksum.update(withInputData: UnsafeRawBufferPointer(buf).prefix(bytesRead))
        }

        return cksum.checksumData
    }

    public init(algorithm: Algorithm) {
        self.algorithm = algorithm

        switch algorithm {
        case .adler32:
            self.backing = .zlib(adler32(0, nil, 0))
        case .crc32:
            self.backing = .zlib(crc32(0, nil, 0))
        case .md2:
            self.backing = .md2((CSChecksum.self as DeprecatedStuff.Type).md2Init())
        case .md5:
            self.backing = .md5((CSChecksum.self as DeprecatedStuff.Type).md5Init())
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
        case .zlib, .data:
            break
        case let .md2(ptr):
            ptr.deallocate()
        case let .md5(ptr):
            ptr.deallocate()
        case let .sha1(ptr):
            ptr.deallocate()
        case let .sha256(ptr):
            ptr.deallocate()
        case let .sha512(ptr):
            ptr.deallocate()
        }
    }

    public func update(withInputData data: some DataProtocol) {
        if data.isEmpty { return }

        let maxLength: Int = {
            switch self.algorithm {
            case .adler32, .crc32:
                return Int(uInt.max)
            case .md2, .md5, .sha1, .sha224, .sha256, .sha384, .sha512:
                return Int(CC_LONG.max)
            }
        }()

        if data.count > maxLength {
            let cutoff = data.index(data.startIndex, offsetBy: maxLength)

            self.update(withInputData: data[..<cutoff])
            self.update(withInputData: data[cutoff...])

            return
        }

        data.regions.forEach {
            $0.withUnsafeBytes {
                let bytes = $0.bindMemory(to: UInt8.self)
                guard let ptr = bytes.baseAddress else { return }

                switch (self.algorithm, self.backing) {
                case (.adler32, .zlib(let cksum)):
                    self.backing = .zlib(adler32(cksum, ptr, uInt(bytes.count)))
                case (.crc32, .zlib(let cksum)):
                    self.backing = .zlib(crc32(cksum, ptr, uInt(bytes.count)))
                case (.md2, .md2(let ctx)):
                    (self as DeprecatedStuff).md2Update(ctx: ctx, ptr: ptr, count: bytes.count)
                case (.md5, .md5(let ctx)):
                    (self as DeprecatedStuff).md5Update(ctx: ctx, ptr: ptr, count: bytes.count)
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

    public var checksumData: some DataProtocol {
        func makeData(count: Int, closure: (UnsafeMutablePointer<UInt8>) -> ()) -> ContiguousArray<UInt8> {
            .init(unsafeUninitializedCapacity: count) { ptr, outCount in
                closure(ptr.baseAddress!)
                outCount = count
            }
        }

        switch self.backing {
        case let .zlib(cksum):
            var crc32 = UInt32(cksum)

            return withUnsafeBytes(of: &crc32) { ContiguousArray($0) }
        case let .md2(ctx):
            let data = (self as DeprecatedStuff).md2Finalize(ctx: ctx)

            self.backing = .data(data)

            return data
        case let .md5(ctx):
            let data = (self as DeprecatedStuff).md5Finalize(ctx: ctx)

            self.backing = .data(data)

            return data
        case let .sha1(ctx):
            let data = makeData(count: Int(CC_SHA1_DIGEST_LENGTH)) { _ = CC_SHA1_Final($0, ctx) }

            ctx.deallocate()
            self.backing = .data(data)

            return data
        case let .sha256(ctx):
            switch self.algorithm {
            case .sha224:
                let data = makeData(count: Int(CC_SHA224_DIGEST_LENGTH)) { _ = CC_SHA224_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return data
            case .sha256:
                let data = makeData(count: Int(CC_SHA256_DIGEST_LENGTH)) { _ = CC_SHA256_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return data
            default:
                fatalError("Illegal backing/algorithm combo")
            }
        case let .sha512(ctx):
            switch self.algorithm {
            case .sha384:
                let data = makeData(count: Int(CC_SHA384_DIGEST_LENGTH)) { _ = CC_SHA384_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return data
            case .sha512:
                let data = makeData(count: Int(CC_SHA512_DIGEST_LENGTH)) { _ = CC_SHA512_Final($0, ctx) }

                ctx.deallocate()
                self.backing = .data(data)

                return data
            default:
                fatalError("Illegal backing/algorithm combo")
            }
        case let .data(data):
            return data
        }
    }
}

private protocol DeprecatedStuff {
    static func md2Init() -> UnsafeMutableRawPointer
    static func md5Init() -> UnsafeMutableRawPointer

    func md2Update(ctx: UnsafeMutableRawPointer, ptr: UnsafePointer<UInt8>, count: Int)
    func md5Update(ctx: UnsafeMutableRawPointer, ptr: UnsafePointer<UInt8>, count: Int)

    func md2Finalize(ctx _ctx: UnsafeMutableRawPointer) -> ContiguousArray<UInt8>
    func md5Finalize(ctx _ctx: UnsafeMutableRawPointer) -> ContiguousArray<UInt8>
}

extension CSChecksum: DeprecatedStuff {
    @available(macOS, deprecated: 10.15)
    static func md2Init() -> UnsafeMutableRawPointer {
        let ctx = UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1)

        CC_MD2_Init(ctx)

        return UnsafeMutableRawPointer(ctx)
    }

    @available(macOS, deprecated: 10.15)
    static func md5Init() -> UnsafeMutableRawPointer {
        let ctx = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)

        CC_MD5_Init(ctx)

        return UnsafeMutableRawPointer(ctx)
    }

    @available(macOS, deprecated: 10.15)
    func md2Update(ctx: UnsafeMutableRawPointer, ptr: UnsafePointer<UInt8>, count: Int) {
        CC_MD2_Update(ctx.bindMemory(to: CC_MD2_CTX.self, capacity: 1), ptr, CC_LONG(count))
    }

    @available(macOS, deprecated: 10.15)
    func md5Update(ctx: UnsafeMutableRawPointer, ptr: UnsafePointer<UInt8>, count: Int) {
        CC_MD5_Update(ctx.bindMemory(to: CC_MD5_CTX.self, capacity: 1), ptr, CC_LONG(count))
    }

    @available(macOS, deprecated: 10.15)
    func md2Finalize(ctx _ctx: UnsafeMutableRawPointer) -> ContiguousArray<UInt8> {
        let count = Int(CC_MD2_DIGEST_LENGTH)

        return .init(unsafeUninitializedCapacity: count) { ptr, outCount in
            let ctx = _ctx.bindMemory(to: CC_MD2_CTX.self, capacity: 1)

            _ = CC_MD2_Final(ptr.baseAddress, ctx)
            outCount = count

            ctx.deallocate()
        }
    }

    @available(macOS, deprecated: 10.15)
    func md5Finalize(ctx _ctx: UnsafeMutableRawPointer) -> ContiguousArray<UInt8> {
        let count = Int(CC_MD5_DIGEST_LENGTH)

        return .init(unsafeUninitializedCapacity: count) { ptr, outCount in
            let ctx = _ctx.bindMemory(to: CC_MD5_CTX.self, capacity: 1)

            _ = CC_MD5_Final(ptr.baseAddress, ctx)
            outCount = count

            ctx.deallocate()
        }
    }
}
