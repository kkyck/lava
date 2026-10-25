/**
 * Base64url helpers.
 *
 * The WhatsApp pairing flow transmits raw key material inside query strings,
 * so it needs the URL-safe base64 alphabet (RFC 4648 section 5) without the
 * `=` padding. The implementation is intentionally tiny and dependency free.
 */

/** The URL-safe base64 alphabet: `+` and `/` are replaced by `-` and `_`. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/**
 * Encodes bytes as an unpadded base64url string.
 *
 * @param bytes The bytes to encode.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
    let out = ''
    let i = 0

    for (; i + 2 < bytes.length; i += 3) {
        const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
        out += ALPHABET[(chunk >> 18) & 0x3f]!
        out += ALPHABET[(chunk >> 12) & 0x3f]!
        out += ALPHABET[(chunk >> 6) & 0x3f]!
        out += ALPHABET[chunk & 0x3f]!
    }

    const remaining = bytes.length - i
    if (remaining === 1) {
        const chunk = bytes[i]! << 16
        out += ALPHABET[(chunk >> 18) & 0x3f]!
        out += ALPHABET[(chunk >> 12) & 0x3f]!
    } else if (remaining === 2) {
        const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8)
        out += ALPHABET[(chunk >> 18) & 0x3f]!
        out += ALPHABET[(chunk >> 12) & 0x3f]!
        out += ALPHABET[(chunk >> 6) & 0x3f]!
    }

    return out
}

/**
 * Decodes an unpadded (or padded) base64url string.
 *
 * Standard base64 input (`+` and `/`) is accepted as well and translated to
 * the URL-safe alphabet, so the helper can be used to normalise values that
 * arrive in either encoding.
 *
 * @param value The text to decode.
 * @returns The decoded bytes, or `undefined` when the input is malformed.
 */
export function base64UrlDecode(value: string): Uint8Array | undefined {
    const clean = value.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
    if (clean.length % 4 === 1) return undefined

    const out = new Uint8Array(Math.floor((clean.length * 3) / 4))
    let outIndex = 0
    let buffer = 0
    let bits = 0

    for (let i = 0; i < clean.length; i++) {
        const index = ALPHABET.indexOf(clean[i]!)
        if (index < 0) return undefined
        buffer = (buffer << 6) | index
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out[outIndex++] = (buffer >> bits) & 0xff
        }
    }

    return out.subarray(0, outIndex)
}
