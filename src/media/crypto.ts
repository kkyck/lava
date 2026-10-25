/**
 * WhatsApp media encryption.
 *
 * A media file never travels in the clear: it is encrypted with a per-file
 * key and uploaded to the WhatsApp CDN. The encryption is
 *
 * ```text
 *   mediaKey (32 bytes)
 *     └─ HKDF-SHA256(info = "WhatsApp <Kind> Keys", 80 bytes)
 *          ├─ iv     [ 0..16)  AES-256-CBC initialisation vector
 *          ├─ encKey [16..48) AES-256-CBC key
 *          └─ macKey [48..80) HMAC-SHA256 key
 * ```
 *
 * The payload on the wire is `AES-256-CBC(plaintext)` followed by the first
 * ten bytes of `HMAC-SHA256(macKey, iv ‖ ciphertext)`. The message stanza
 * carries the media key and the two SHA-256 hashes (of the plaintext and of
 * the encrypted bytes), so a recipient can verify what it downloaded.
 */

import {
    aesCbcDecrypt,
    aesCbcEncrypt,
    concat,
    equalBytes,
    hkdf,
    hmacSha256,
    sha256,
    utf8,
} from '../crypto/primitives.js'

/** The length of a media key. */
export const MEDIA_KEY_LENGTH = 32

/** The length of the HKDF expansion. */
export const MEDIA_HKDF_SIZE = 80

/** The offset of the AES key inside the HKDF expansion. */
export const MEDIA_ENC_KEY_START = 16

/** The end of the AES key inside the HKDF expansion. */
export const MEDIA_ENC_KEY_END = 48

/** The offset of the MAC key inside the HKDF expansion. */
export const MEDIA_MAC_KEY_START = 48

/** The end of the MAC key inside the HKDF expansion. */
export const MEDIA_MAC_KEY_END = 80

/** The length of the truncated HMAC that is appended to the ciphertext. */
export const MEDIA_MAC_LENGTH = 10

/** The media kinds WhatsApp derives separate keys for. */
export const MEDIA_HKDF_INFO: Readonly<Record<string, Uint8Array>> = Object.freeze({
    document: utf8('WhatsApp Document Keys'),
    image: utf8('WhatsApp Image Keys'),
    sticker: utf8('WhatsApp Image Keys'),
    video: utf8('WhatsApp Video Keys'),
    gif: utf8('WhatsApp Video Keys'),
    audio: utf8('WhatsApp Audio Keys'),
    ptt: utf8('WhatsApp Audio Keys'),
    'sticker-pack': utf8('WhatsApp Sticker Pack Keys'),
    'thumbnail-sticker-pack': utf8('WhatsApp Sticker Pack Thumbnail Keys'),
    'thumbnail-link': utf8('WhatsApp Link Thumbnail Keys'),
})

/**
 * Returns the HKDF `info` bytes for a media kind.
 *
 * @param mediaType The media kind (`image`, `video`, `audio`, …).
 */
export function getMediaHkdfInfo(mediaType: string): Uint8Array {
    const info = MEDIA_HKDF_INFO[mediaType]
    if (!info) throw new Error(`unsupported media type: ${mediaType}`)
    return info
}

/** The keys derived from a media key. */
export interface MediaKeys {
    /** The 16-byte AES initialisation vector. */
    iv: Uint8Array
    /** The 32-byte AES key. */
    encKey: Uint8Array
    /** The 32-byte HMAC key. */
    macKey: Uint8Array
}

/**
 * Derives the AES and MAC keys from a media key.
 *
 * @param mediaType The media kind.
 * @param mediaKey The 32-byte media key.
 */
export function deriveMediaKeys(mediaType: string, mediaKey: Uint8Array): MediaKeys {
    if (mediaKey.length !== MEDIA_KEY_LENGTH) {
        throw new Error(`invalid media key length ${mediaKey.length}`)
    }
    const expanded = hkdf(mediaKey, null, getMediaHkdfInfo(mediaType), MEDIA_HKDF_SIZE)
    return {
        iv: expanded.subarray(0, 16),
        encKey: expanded.subarray(MEDIA_ENC_KEY_START, MEDIA_ENC_KEY_END),
        macKey: expanded.subarray(MEDIA_MAC_KEY_START, MEDIA_MAC_KEY_END),
    }
}

/** The result of encrypting a media payload. */
export interface EncryptedMedia {
    /** The ciphertext with the truncated MAC appended. */
    ciphertextHmac: Uint8Array
    /** The SHA-256 of the plaintext. */
    fileSha256: Uint8Array
    /** The SHA-256 of the encrypted payload. */
    fileEncSha256: Uint8Array
    /** The length of the plaintext. */
    plaintextLength: number
}

/**
 * Encrypts a media payload.
 *
 * @param mediaType The media kind.
 * @param mediaKey The 32-byte media key.
 * @param plaintext The media bytes.
 */
export function encryptMedia(
    mediaType: string,
    mediaKey: Uint8Array,
    plaintext: Uint8Array,
): EncryptedMedia {
    const keys = deriveMediaKeys(mediaType, mediaKey)
    const ciphertext = aesCbcEncrypt(keys.encKey, keys.iv, plaintext)
    const mac = hmacSha256(keys.macKey, keys.iv, ciphertext).subarray(0, MEDIA_MAC_LENGTH)
    const ciphertextHmac = concat(ciphertext, mac)
    return {
        ciphertextHmac,
        fileSha256: sha256(plaintext),
        fileEncSha256: sha256(ciphertextHmac),
        plaintextLength: plaintext.length,
    }
}

/** The result of decrypting a media payload. */
export interface DecryptedMedia {
    /** The decrypted media bytes. */
    plaintext: Uint8Array
    /** The SHA-256 of the plaintext. */
    fileSha256: Uint8Array
    /** The SHA-256 of the encrypted payload. */
    fileEncSha256: Uint8Array
}

/**
 * Decrypts a media payload and verifies its integrity.
 *
 * The MAC is always verified. The two SHA-256 hashes are verified when the
 * message stanza carries them, so a tampered download is rejected instead of
 * being handed to the caller.
 *
 * @param mediaType The media kind.
 * @param mediaKey The 32-byte media key.
 * @param ciphertextHmac The encrypted payload with the MAC appended.
 * @param expectedFileSha256 The expected SHA-256 of the plaintext.
 * @param expectedFileEncSha256 The expected SHA-256 of the encrypted payload.
 */
export function decryptMedia(
    mediaType: string,
    mediaKey: Uint8Array,
    ciphertextHmac: Uint8Array,
    expectedFileSha256?: Uint8Array,
    expectedFileEncSha256?: Uint8Array,
): DecryptedMedia {
    if (ciphertextHmac.length < MEDIA_MAC_LENGTH) {
        throw new Error(`media ciphertext too short: ${ciphertextHmac.length}`)
    }

    const fileEncSha256 = sha256(ciphertextHmac)
    if (expectedFileEncSha256 && !equalBytes(fileEncSha256, expectedFileEncSha256)) {
        throw new Error('media encrypted hash mismatch')
    }

    const keys = deriveMediaKeys(mediaType, mediaKey)
    const cipherLength = ciphertextHmac.length - MEDIA_MAC_LENGTH
    const ciphertext = ciphertextHmac.subarray(0, cipherLength)
    const expectedMac = ciphertextHmac.subarray(cipherLength)

    const mac = hmacSha256(keys.macKey, keys.iv, ciphertext).subarray(0, MEDIA_MAC_LENGTH)
    if (!equalBytes(mac, expectedMac)) {
        throw new Error('media MAC mismatch')
    }

    const plaintext = aesCbcDecrypt(keys.encKey, keys.iv, ciphertext)
    const fileSha256 = sha256(plaintext)
    if (expectedFileSha256 && !equalBytes(fileSha256, expectedFileSha256)) {
        throw new Error('media plaintext hash mismatch')
    }

    return { plaintext, fileSha256, fileEncSha256 }
}

/**
 * Returns the length of the encrypted payload for a given plaintext length.
 *
 * @param plaintextLength The length of the plaintext.
 */
export function encryptedMediaLength(plaintextLength: number): number {
    if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
        throw new Error(`invalid plaintext length ${plaintextLength}`)
    }
    return (Math.floor(plaintextLength / 16) + 1) * 16 + MEDIA_MAC_LENGTH
}
