//
//  CSChecksum_Foundation.swift
//  
//
//  Created by Charles Srstka on 1/1/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import CSDataProtocol
import CSDataProtocol_Foundation
import CSChecksum

extension CSChecksum {
    @available(macOS 10.15.4, macCatalyst 13.4, iOS 13.4, tvOS 13.4, watchOS 6.2, *)
    public static func checksum(
        at url: URL,
        algorithm: CSChecksumAlgorithm
    ) throws -> some CSDataProtocol.DataProtocol where Raw == ContiguousArray<UInt8> {
        let handle = try FileHandle(forReadingFrom: url)
        defer { _ = try? handle.close() }

        var cksum = CSChecksum(algorithm: algorithm)

        while let data = try autoreleasepool(invoking: { try handle.read(upToCount: defaultBufsize) }), !data.isEmpty {
            cksum.update(withInputData: data)
        }

        return cksum.finalize()
    }
}
