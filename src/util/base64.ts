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
    return base64UrlEncodeInner(bytes, false)
}

/**
 * Encodes bytes as a **padded** base64url string.
 *
 * The WhatsApp media CDN expects the padded form: the official client takes
 * the standard base64 of the file hash and only swaps `+` for `-` and `/` for
 * `_`, so the `=` padding survives. The CDN derives the expected hash from
 * the path segment, and a strict decoder rejects an unpadded string.
 *
 * @param bytes The bytes to encode.
 */
export function base64UrlEncodePadded(bytes: Uint8Array): string {
    return base64UrlEncodeInner(bytes, true)
}

/**
 * Encodes bytes as a base64url string.
 *
 * @param bytes The bytes to encode.
 * @param padded Whether the `=` padding is kept.
 */
function base64UrlEncodeInner(bytes: Uint8Array, padded: boolean): string {
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

    if (padded) {
        const remainder = bytes.length % 3
        if (remainder === 1) out += '=='
        else if (remainder === 2) out += '='
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
