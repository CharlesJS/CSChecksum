//
//  DeprecatedStuff.swift
//  CSChecksum
//
//  Created by Charles Srstka on 1/26/25.
//

import CommonCrypto

internal let deprecatedStuff: some DeprecatedStuff = DeprecatedStuffImplementation()

internal protocol DeprecatedStuff: Sendable {
    func md2Init() -> UnsafeMutableRawPointer
    func md5Init() -> UnsafeMutableRawPointer

    func md2Update(ctx: UnsafeMutableRawPointer, ptr: UnsafePointer<UInt8>, count: Int)
    func md5Update(ctx: UnsafeMutableRawPointer, ptr: UnsafePointer<UInt8>, count: Int)

    func md2Finalize(ctx _ctx: UnsafeMutableRawPointer) -> ContiguousArray<UInt8>
    func md5Finalize(ctx _ctx: UnsafeMutableRawPointer) -> ContiguousArray<UInt8>
}

private struct DeprecatedStuffImplementation: DeprecatedStuff {
    @available(macOS, deprecated: 10.15)
    func md2Init() -> UnsafeMutableRawPointer {
        let ctx = UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1)

        CC_MD2_Init(ctx)

        return UnsafeMutableRawPointer(ctx)
    }

    @available(macOS, deprecated: 10.15)
    func md5Init() -> UnsafeMutableRawPointer {
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
