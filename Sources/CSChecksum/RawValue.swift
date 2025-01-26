//
//  RawValue.swift
//  CSChecksum
//
//  Created by Charles Srstka on 1/26/25.
//

public protocol RawValue {
    init(checksumBytes: ContiguousArray<UInt8>)
    init(checksumInteger: some FixedWidthInteger)
}

extension ContiguousArray<UInt8>: RawValue {
    public init(checksumBytes: ContiguousArray<UInt8>) {
        self = checksumBytes
    }

    public init<I: FixedWidthInteger>(checksumInteger: I) {
        self = ContiguousArray<UInt8>(unsafeUninitializedCapacity: MemoryLayout<I>.size) { buf, count in
            buf.withMemoryRebound(to: I.self) { $0[0] = checksumInteger }
            count = MemoryLayout<I>.size
        }
    }
}

extension UInt32: RawValue {
    public init(checksumBytes: ContiguousArray<UInt8>) {
        precondition(checksumBytes.count == 4)
        self = checksumBytes.withUnsafeBytes { $0.withMemoryRebound(to: UInt32.self) { $0[0] } }
    }

    public init(checksumInteger: some FixedWidthInteger) {
        self = UInt32(checksumInteger)
    }
}
