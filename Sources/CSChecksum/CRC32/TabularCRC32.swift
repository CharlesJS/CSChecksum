//
//  TabularCRC32.swift
//  CSChecksum
//
//  Created by Charles Srstka on 1/26/25.
//

import SyncPolyfill

internal struct TabularCRC32 {
    internal static let crc32ReversePoly: UInt32 = 0xedb88320
    internal static let crc32CReversePoly: UInt32 = 0x82f63b78

    private static let tablesMutex = Mutex<[UInt32 : [UInt32]]>([:])

    internal static func getCRC32Table(poly: UInt32) -> [UInt32] {
        self.tablesMutex.withLock { tables in
            if let table = tables[poly] {
                return table
            }
            
            let table = generateCRC32Table(poly: poly)
            tables[poly] = table
            return table
        }
    }

    private static func generateCRC32Table(poly: UInt32) -> [UInt32] {
        let tableCount = 16
        var table: [UInt32] = []
        table.reserveCapacity(tableCount &* 256)

        for i: UInt32 in 0..<256 {
            table.append((0..<8).reduce(i) { crc, _ in
                (crc & 1 != 0) ? (crc &>> 1) ^ poly : crc &>> 1
            })
        }

        for i in 256..<Int(tableCount &* 256) {
            let r = table[i &- 256]
            table.append((r &>> 8) ^ table[Int(r & 0xff)])
        }

        return table
    }

    internal static func calculateCRC32(
        _ data: some Collection<UInt8>,
        initialValue: UInt32,
        table: [UInt32]
    ) -> UInt32 {
        let (crc, bytesUsed) = data.withContiguousStorageIfAvailable { bytes in
            var crc = ~initialValue

            guard let baseAddress = UnsafeRawBufferPointer(bytes).baseAddress else { return (crc, 0) }
            let aligned = baseAddress.alignedUp(for: UInt64.self)
            let toAlign = min(aligned - baseAddress, bytes.count)

            for byte in bytes.prefix(toAlign) {
                crc = (crc &>> 8) ^ table[Int(crc ^ UInt32(byte)) & 0xff]
            }

            return bytes.dropFirst(toAlign).withMemoryRebound(to: (UInt32, UInt32, UInt32, UInt32).self) { buf in
                for (r1, r2, r3, r4) in buf {
                    let r = crc ^ r1

                    crc = (
                        table[0 &* 256 &+ Int((r4 &>> 24) & 0xff)] ^
                        table[1 &* 256 &+ Int((r4 &>> 16) & 0xff)] ^
                        table[2 &* 256 &+ Int((r4 &>> 8) & 0xff)] ^
                        table[3 &* 256 &+ Int((r4 &>> 0) & 0xff)] ^
                        table[4 &* 256 &+ Int((r3 &>> 24) & 0xff)] ^
                        table[5 &* 256 &+ Int((r3 &>> 16) & 0xff)] ^
                        table[6 &* 256 &+ Int((r3 &>> 8) & 0xff)] ^
                        table[7 &* 256 &+ Int((r3 &>> 0) & 0xff)] ^
                        table[8 &* 256 &+ Int((r2 &>> 24) & 0xff)] ^
                        table[9 &* 256 &+ Int((r2 &>> 16) & 0xff)] ^
                        table[10 &* 256 &+ Int((r2 &>> 8) & 0xff)] ^
                        table[11 &* 256 &+ Int((r2 &>> 0) & 0xff)] ^
                        table[12 &* 256 &+ Int((r &>> 24) & 0xff)] ^
                        table[13 &* 256 &+ Int((r &>> 16) & 0xff)] ^
                        table[14 &* 256 &+ Int((r &>> 8) & 0xff)] ^
                        table[15 &* 256 &+ Int(r & 0xff)]
                    )
                }

                return (crc, buf.count &* 16 &+ toAlign)
            }
        } ?? (~initialValue, 0)

        return ~data.dropFirst(bytesUsed).reduce(crc) { crc, byte in
            (crc &>> 8) ^ table[Int(crc ^ UInt32(byte)) & 0xff]
        }
    }
}
