
import Foundation

@inline(__always)
func dataToHex(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

@inline(__always)
func hexToData(_ hex: String) -> Data? {
    var hex = hex
    if hex.hasPrefix("0x") { hex = String(hex.dropFirst(2)) }
    let len = hex.count
    if len % 2 != 0 { return nil }
    var data = Data(capacity: len/2)
    var idx = hex.startIndex
    for _ in 0..<(len/2) {
        let nextIndex = hex.index(idx, offsetBy: 2)
        let byteString = hex[idx..<nextIndex]
        if let b = UInt8(byteString, radix: 16) {
            data.append(b)
        } else {
            return nil
        }
        idx = nextIndex
    }
    return data
}
