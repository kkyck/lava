/**
 * WhatsApp QR pairing payloads.
 *
 * When the user scans the QR code shown by a companion device, the phone
 * expects a payload with five comma-separated fields:
 *
 * ```text
 *   <ref>,<noisePubKey>,<identityPubKey>,<advSecret>,<devicePlatform>
 * ```
 *
 * - `ref` is the pairing reference the server handed out with the
 *   `<pair-device>` stanza. It is opaque and passed through unchanged.
 * - `noisePubKey` is this device's Noise static public key.
 * - `identityPubKey` is this device's Signal identity public key.
 * - `advSecret` is the Advanced Device Attestation secret.
 * - `devicePlatform` is the client type of this program, e.g. `7` for the
 *   desktop app.
 *
 * All binary values are standard base64 with padding, exactly as the
 * official client encodes them.
 */

import { base64UrlDecode, base64UrlEncode } from '../util/base64.js'

export { base64UrlDecode, base64UrlEncode } from '../util/base64.js'

/** The client version advertised in the pairing payload by default. */
export const DEFAULT_CLIENT_VERSION = '2.3000.1043028647'

/** The standard base64 alphabet with the `+` and `/` characters. */
const STANDARD_ALPHABET =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/**
 * Encodes bytes as a padded standard base64 string.
 *
 * @param bytes The bytes to encode.
 */
export function base64Encode(bytes: Uint8Array): string {
    let out = ''
    let i = 0

    for (; i + 2 < bytes.length; i += 3) {
        const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
        out += STANDARD_ALPHABET[(chunk >> 18) & 0x3f]!
        out += STANDARD_ALPHABET[(chunk >> 12) & 0x3f]!
        out += STANDARD_ALPHABET[(chunk >> 6) & 0x3f]!
        out += STANDARD_ALPHABET[chunk & 0x3f]!
    }

    const remaining = bytes.length - i
    if (remaining === 1) {
        const chunk = bytes[i]! << 16
        out += STANDARD_ALPHABET[(chunk >> 18) & 0x3f]!
        out += STANDARD_ALPHABET[(chunk >> 12) & 0x3f]!
        out += '=='
    } else if (remaining === 2) {
        const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8)
        out += STANDARD_ALPHABET[(chunk >> 18) & 0x3f]!
        out += STANDARD_ALPHABET[(chunk >> 12) & 0x3f]!
        out += STANDARD_ALPHABET[(chunk >> 6) & 0x3f]!
        out += '='
    }

    return out
}

/**
 * Decodes a padded standard base64 string.
 *
 * @param value The text to decode.
 * @returns The decoded bytes, or `undefined` when the input is malformed.
 */
export function base64Decode(value: string): Uint8Array | undefined {
    const clean = value.replace(/=+$/, '')
    const normalized = clean.replace(/-/g, '+').replace(/_/g, '/')
    if (normalized.length % 4 === 1) return undefined

    const out = new Uint8Array(Math.floor((normalized.length * 3) / 4))
    let outIndex = 0
    let buffer = 0
    let bits = 0

    for (let i = 0; i < normalized.length; i++) {
        const index = STANDARD_ALPHABET.indexOf(normalized[i]!)
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

/** Parameters needed to build a WhatsApp pairing QR payload. */
export interface WhatsAppQrParams {
    /** The pairing reference returned by the server. */
    ref: string
    /** This device's Noise static public key. */
    noisePublicKey: Uint8Array
    /** This device's Signal identity public key. */
    identityPublicKey: Uint8Array
    /** The Advanced Device Attestation secret. */
    advSecret: Uint8Array
    /** The client type of this program, e.g. `7` for the desktop app. */
    devicePlatform: string
}

/**
 * Builds the payload string of a WhatsApp pairing QR code.
 *
 * @param params The pairing parameters.
 */
export function buildWhatsAppQrPayload(params: WhatsAppQrParams): string {
    return [
        params.ref,
        base64Encode(params.noisePublicKey),
        base64Encode(params.identityPublicKey),
        base64Encode(params.advSecret),
        params.devicePlatform,
    ].join(',')
}

/**
 * Parses a WhatsApp pairing QR payload back into its parts.
 *
 * @param payload The scanned payload.
 */
export function parseWhatsAppQrPayload(payload: string): WhatsAppQrParams | null {
    const parts = payload.split(',')
    if (parts.length < 5) return null
    const [ref, noise, identity, adv, ...rest] = parts
    if (!ref || !noise || !identity || !adv) return null
    const noisePublicKey = base64Decode(noise)
    const identityPublicKey = base64Decode(identity)
    const advSecret = base64Decode(adv)
    if (!noisePublicKey || !identityPublicKey || !advSecret) return null
    return {
        ref,
        noisePublicKey,
        identityPublicKey,
        advSecret,
        devicePlatform: rest.join(','),
    }
}
