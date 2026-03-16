//
//  HardwareCapabilities.swift
//  CSChecksum
//
//  Created by Charles Srstka on 1/26/25.
//

#if canImport(Darwin)
import Darwin

private func supportsFeature(name: String) -> Bool {
    var len: Int = 0

    return sysctlbyname(name, nil, &len, nil, 0) == 0 && withUnsafeTemporaryAllocation(byteCount: len, alignment: 1) {
        sysctlbyname(name, $0.baseAddress, &len, nil, 0) == 0 && $0.contains { $0 != 0 }
    }
}

#if arch(arm64)
internal let supportsFusionCRC32: Bool = (
    supportsFeature(name: "hw.optional.armv8_crc32") &&
    supportsFeature(name: "hw.optional.arm.FEAT_PMULL") &&
    supportsFeature(name: "hw.optional.arm.FEAT_SHA3")
)

internal let supportsFusionCRC32C = supportsFusionCRC32
#elseif arch(x86_64)
private let featureSet: Set<Substring> = {
    let name = "machdep.cpu.features"
    var len: Int = 0

    guard sysctlbyname(name, nil, &len, nil, 0) == 0 else { return [] }
    return withUnsafeTemporaryAllocation(byteCount: len, alignment: 1) {
        guard sysctlbyname(name, $0.baseAddress, &len, nil, 0) == 0 else { return [] }

        return Set(String(decoding: $0, as: UTF8.self).split(separator: " "))
    }
}()

internal let supportsFusionCRC32 = false

internal let supportsFusionCRC32C: Bool = (
    featureSet.contains("PCLMULQDQ") && featureSet.contains("SSE4.2")
)
#else // unknown arch
internal let supportsFusionCRC32 = false
internal let supportsFusionCRC32C = false
#endif

#else // !canImport(Darwin)
import asm

internal let supportsFusionCRC32C = supports_fusion_crc32c()

#if arch(arm64)
internal let supportsFusionCRC32 = supportsFusionCRC32C
#else
internal let supportsFusionCRC32 = false
#endif
#endif
