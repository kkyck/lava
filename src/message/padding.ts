/**
 * Message padding.
 *
 * WhatsApp pads the plaintext of every message with 1-16 random bytes before
 * encrypting it. The padding hides the exact length of the plaintext, which
 * would otherwise leak the size of a message to a passive observer.
 *
 * The padding byte value equals the padding length, so the receiver can strip
 * it deterministically.
 */

import { randomBytes } from 'node:crypto'

/** The padding length is a random value in `1..16`. */
const RANDOM_PAD_MAX_16_MASK = 0x0f

/**
 * Pads a message with 1-16 random bytes.
 *
 * @param message The plaintext.
 */
export function writeRandomPadMax16(message: Uint8Array): Uint8Array {
    const padLength = (randomBytes(1)[0]! & RANDOM_PAD_MAX_16_MASK) + 1
    const out = new Uint8Array(message.length + padLength)
    out.set(message, 0)
    out.fill(padLength, message.length)
    return out
}

/**
 * Removes the padding added by {@link writeRandomPadMax16}.
 *
 * @param bytes The padded plaintext.
 */
export function unpadPkcs7(bytes: Uint8Array): Uint8Array {
    if (bytes.length === 0) {
        throw new Error('unpadPkcs7 given empty bytes')
    }
    const padLength = bytes[bytes.length - 1]!
    if (padLength > bytes.length) {
        throw new Error(`unpadPkcs7 given ${bytes.length} bytes, but pad is ${padLength}`)
    }
    return bytes.subarray(0, bytes.length - padLength)
}
