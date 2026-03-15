//
//  CSChecksumAlgorithm.swift
//  CSChecksum
//
//  Created by Charles Srstka on 1/26/25.
//

public enum CSChecksumAlgorithm: Codable, CustomStringConvertible, Hashable, Sendable {
    case adler32
    case posix
    case crc32
    case crc32c
    case fletcher64(withCheckBytes: Bool)
#if Crypto
    case md5     // WARNING: Not secure. Included for use in parsing legacy file types only.
    case sha1    // WARNING: Not secure. Included for use in parsing legacy file types only.
    case sha256
    case sha512

#if canImport(CommonCrypto)
    case md2     // WARNING: Not secure. Included for use in parsing legacy file types only.
    case sha224
    case sha384
#endif
#endif

    public var description: String {
        switch self {
        case .adler32:
            return "Adler32"
        case .crc32:
            return "CRC32"
        case .crc32c:
            return "CRC32C"
        case .fletcher64(let withCheckBytes):
            return "Fletcher64 " + (withCheckBytes ? "with" : "without") + " check bytes"
        case .posix:
            return "POSIX"
#if Crypto
        case .md5:
            return "MD5"
        case .sha1:
            return "SHA1"
        case .sha256:
            return "SHA256"
        case .sha512:
            return "SHA512"
#if canImport(CommonCrypto)
        case .md2:
            return "MD2"
        case .sha224:
            return "SHA224"
        case .sha384:
            return "SHA384"
#endif
#endif
        }
    }
}
