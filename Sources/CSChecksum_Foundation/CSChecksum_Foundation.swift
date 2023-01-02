//
//  CSChecksum_Foundation.swift
//  
//
//  Created by Charles Srstka on 1/1/23.
//

import Foundation
import CSDataProtocol
import CSDataProtocol_Foundation
@_spi(CSChecksumInternal) import CSChecksum

extension CSChecksum {
    @available(macOS 10.15.4, macCatalyst 13.4, iOS 13.4, tvOS 13.4, watchOS 6.2, *)
    public static func checksum(at url: URL, algorithm: Algorithm) throws -> some CSDataProtocol.DataProtocol {
        let handle = try FileHandle(forReadingFrom: url)
        defer { _ = try? handle.close() }

        let cksum = CSChecksum(algorithm: algorithm)

        while let data = try autoreleasepool(invoking: { try handle.read(upToCount: CSChecksum.bufsize) }), !data.isEmpty {
            cksum.update(withInputData: data)
        }

        return cksum.checksumData
    }
}
