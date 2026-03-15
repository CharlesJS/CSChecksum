//
//  Fletcher.swift
//  CSChecksum
//
//  Created by Charles Srstka on 1/27/25.
//

// Based on implementations from:
// https://www.intel.com/content/www/us/en/developer/articles/technical/fast-computation-of-fletcher-checksums.html
// https://github.com/google/wuffs/blob/main/std/adler32/common_up_arm_neon.wuffs

struct Fletcher {
    static func fletcher64(
        bytes: UnsafeRawBufferPointer,
        lowSum: UInt64 = 0,
        highSum: UInt64 = 0
    ) -> (lowSum: UInt64, highSum: UInt64) {
        if bytes.baseAddress?.alignedUp(for: UInt32.self) == bytes.baseAddress {
            let new = self.fletcher64(
                buffer: bytes.bindMemory(to: UInt32.self),
                lowSum: lowSum,
                highSum: highSum
            )

            return new
        } else {
            return withUnsafeTemporaryAllocation(of: UInt32.self, capacity: bytes.count / MemoryLayout<UInt32>.stride) { buf in
                _ = buf.withMemoryRebound(to: UInt8.self) {
                    $0.initialize(from: bytes)
                }

                return fletcher64(
                    buffer: UnsafeBufferPointer(buf),
                    lowSum: lowSum,
                    highSum: highSum
                )
            }
        }
    }

    static func fletcher64(
        buffer: UnsafeBufferPointer<UInt32>,
        lowSum: UInt64 = 0,
        highSum: UInt64 = 0
    ) -> (lowSum: UInt64, highSum: UInt64) {
        let modValue = UInt64(UInt32.max)

        let (prefix, vectors, suffix) = self.realignBuffer(buffer, to: SIMD4<UInt32>.self)

        var lo = lowSum
        var hi = highSum
        for word in prefix {
            lo &+= UInt64(word)
            hi &+= lo
        }

        lo %= modValue
        hi %= modValue

        for i in stride(from: vectors.startIndex, to: vectors.endIndex, by: 347) {
            let chunk = vectors[i...].prefix(92681)

            hi &+= lo &* UInt64(truncatingIfNeeded: chunk.count &<< 2)

            var vLo = SIMD2<UInt64>.zero
            var vHi = SIMD2<UInt64>.zero

            var col0 = SIMD2<UInt64>.zero
            var col1 = SIMD2<UInt64>.zero

            for vec in chunk {
                vHi &+= vLo

                vLo &+= SIMD2<UInt64>(truncatingIfNeeded: vec.lowHalf) &+ SIMD2<UInt64>(truncatingIfNeeded: vec.highHalf)

                col0 &+= SIMD2<UInt64>(truncatingIfNeeded: vec.lowHalf)
                col1 &+= SIMD2<UInt64>(truncatingIfNeeded: vec.highHalf)
            }

            vHi &<<= 2
            vHi &+= col0 &* SIMD2<UInt64>(4, 3)
            vHi &+= col1 &* SIMD2<UInt64>(2, 1)

            lo = (lo &+ UInt64(truncatingIfNeeded: vLo.wrappedSum())) % modValue
            hi = (hi &+ UInt64(truncatingIfNeeded: vHi.wrappedSum())) % modValue
        }

        for byte in suffix {
            lo &+= UInt64(byte)
            hi &+= lo
        }

        return (lowSum: lo % modValue, highSum: hi % modValue)
    }

    static func fletcher64Finalize(lowSum lo: UInt64, highSum hi: UInt64, includeCheckBytes: Bool) -> UInt64 {
        if includeCheckBytes {
            let modValue = UInt64(UInt32.max)

            let check1 = modValue &- ((lo &+ hi) % modValue)
            let check2 = modValue &- ((lo &+ check1) % modValue)

            return (check2 &<< 32) | check1
        }

        return (hi &<< 32) | lo
    }

    static func adler32(bytes: UnsafeRawBufferPointer, initialValue: UInt32 = 1) -> UInt32 {
        let modValue: UInt64 = 65521

        let (prefix, vectors, suffix) = self.realignBuffer(bytes, to: SIMD16<UInt8>.self)

        var lo = UInt64(truncatingIfNeeded: initialValue & 0xffff)
        var hi = UInt64(truncatingIfNeeded: initialValue &>> 16)
        for byte in prefix {
            lo &+= UInt64(byte)
            hi &+= lo
        }

        lo %= modValue
        hi %= modValue

        for i in stride(from: vectors.startIndex, to: vectors.endIndex, by: 347) {
            let chunk = vectors[i...].prefix(347)

            hi &+= lo &* UInt64(truncatingIfNeeded: chunk.count &<< 4)

            var vLo = SIMD4<UInt32>.zero
            var vHi = SIMD4<UInt32>.zero

            var col0 = SIMD8<UInt16>.zero
            var col1 = SIMD8<UInt16>.zero

            for vec in chunk {
                vHi &+= vLo

                vLo &+= SIMD4<UInt32>(truncatingIfNeeded: vec.lowHalf.lowHalf) &+
                SIMD4<UInt32>(truncatingIfNeeded: vec.lowHalf.highHalf) &+
                SIMD4<UInt32>(truncatingIfNeeded: vec.highHalf.lowHalf) &+
                SIMD4<UInt32>(truncatingIfNeeded: vec.highHalf.highHalf)

                col0 &+= SIMD8<UInt16>(truncatingIfNeeded: vec.lowHalf)
                col1 &+= SIMD8<UInt16>(truncatingIfNeeded: vec.highHalf)
            }

            vHi &<<= 4
            vHi &+= SIMD4<UInt32>(truncatingIfNeeded: col0.lowHalf) &* SIMD4<UInt32>(16, 15, 14, 13)
            vHi &+= SIMD4<UInt32>(truncatingIfNeeded: col0.highHalf) &* SIMD4<UInt32>(12, 11, 10, 9)
            vHi &+= SIMD4<UInt32>(truncatingIfNeeded: col1.lowHalf) &* SIMD4<UInt32>(8, 7, 6, 5)
            vHi &+= SIMD4<UInt32>(truncatingIfNeeded: col1.highHalf) &* SIMD4<UInt32>(4, 3, 2, 1)

            lo = (lo &+ UInt64(truncatingIfNeeded: vLo.wrappedSum())) % modValue
            hi = (hi &+ UInt64(truncatingIfNeeded: vHi.wrappedSum())) % modValue
        }

        for byte in suffix {
            lo &+= UInt64(byte)
            hi &+= lo
        }

        lo %= modValue
        hi %= modValue

        return UInt32(truncatingIfNeeded: (hi &<< 16) | lo)
    }

    @inline(__always)
    private static func adler32Combine(
        lo1: UInt64,
        hi1: UInt64,
        lo2: UInt64,
        hi2: UInt64,
        len2: UInt64,
        modValue: UInt64
    ) -> (lo: UInt64, hi: UInt64) {
        let rem = len2 % modValue
        let sum1 = lo1 &+ lo2 &+ modValue &- 1
        let sum2 = rem &* lo1 &+ hi1 &+ hi2 &+ modValue &- rem

        return (lo: sum1 % modValue, hi: sum2 % modValue)
    }

    @inline(__always)
    private static func realignBuffer<Source, Dest>(_ buffer: UnsafeBufferPointer<Source>, to dest: Dest.Type) -> (
        prefix: UnsafeBufferPointer<Source>,
        aligned: UnsafeBufferPointer<Dest>,
        suffix: UnsafeBufferPointer<Source>
    ) {
        let (prefix, aligned, suffix) = self.realignBuffer(UnsafeRawBufferPointer(buffer), to: dest)

        return (prefix.assumingMemoryBound(to: Source.self), aligned, suffix.assumingMemoryBound(to: Source.self))
    }

    @inline(__always)
    private static func realignBuffer<Dest>(_ buffer: UnsafeRawBufferPointer, to dest: Dest.Type) -> (
        prefix: UnsafeRawBufferPointer,
        aligned: UnsafeBufferPointer<Dest>,
        suffix: UnsafeRawBufferPointer
    ) {
        guard let baseAddress = buffer.baseAddress else {
            return (
                prefix: UnsafeRawBufferPointer(start: nil, count: 0),
                aligned: UnsafeBufferPointer(start: nil, count: 0),
                suffix: UnsafeRawBufferPointer(start: nil, count: 0)
            )
        }

        let endAddress = baseAddress + buffer.count

        let alignedStart = min(endAddress, baseAddress.alignedUp(for: Dest.self))
        let count = (endAddress - alignedStart) / MemoryLayout<Dest>.stride

        let suffixStart = alignedStart + count &* MemoryLayout<Dest>.stride

        return (
            prefix: UnsafeRawBufferPointer(start: baseAddress, count: alignedStart - baseAddress),
            aligned: UnsafeBufferPointer(start: alignedStart.bindMemory(to: Dest.self, capacity: count), count: count),
            suffix: UnsafeRawBufferPointer(start: suffixStart, count: endAddress - suffixStart)
        )
    }
}
