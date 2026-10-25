/**
 * Message id generation.
 *
 * WhatsApp message ids are opaque strings that the server echoes back in
 * acknowledgements, receipts and retries, so they have to look like the ids
 * the official client produces.
 *
 * Two formats exist, and the difference is visible to the server:
 *
 * - **WhatsApp Web** — a 22 character id that starts with `3EB0`. It is
 *   derived from the current time (in seconds), the account's own JID and 8
 *   random bytes, hashed with SHA-256.
 * - **Mobile (WAP)** — a 32 character id with the first byte forced to
 *   `0xac`. It is derived from the current time (in milliseconds), the
 *   account's own JID and 16 random bytes, hashed with MD5.
 *
 * Both formats embed the timestamp, which lets the server order the ids and
 * lets the client detect a replay.
 */

import { md5, randomBytesOf, sha256, toHex, utf8 } from '../crypto/primitives.js'

/** The prefix every WhatsApp Web message id starts with. */
export const WEB_MESSAGE_ID_PREFIX = '3EB0'

/** The first byte of every mobile message id. */
export const MOBILE_MESSAGE_ID_FIRST_BYTE = 0xac

/**
 * Generates a WhatsApp Web style message id.
 *
 * @param meJid The account's own JID.
 */
export function generateWebMessageId(meJid: string): string {
    const timestamp = new Uint8Array(8)
    const view = new DataView(timestamp.buffer, timestamp.byteOffset, timestamp.byteLength)
    view.setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), false)
    const digest = sha256(timestamp, utf8(meJid), randomBytesOf(8))
    return WEB_MESSAGE_ID_PREFIX + toHex(digest.subarray(0, 9)).toUpperCase()
}

/**
 * Generates a mobile (WAP) style message id.
 *
 * @param meJid The account's own JID.
 */
export function generateMobileMessageId(meJid: string): string {
    const timestamp = new Uint8Array(8)
    const view = new DataView(timestamp.buffer, timestamp.byteOffset, timestamp.byteLength)
    view.setBigUint64(0, BigInt(Date.now()), false)
    const digest = md5(timestamp, utf8(meJid), randomBytesOf(16))
    digest[0] = MOBILE_MESSAGE_ID_FIRST_BYTE
    return toHex(digest).toUpperCase()
}

/** The message id formats the client supports. */
export type MessageIdFormat = 'web' | 'mobile'

/**
 * Generates a message id in the requested format.
 *
 * @param meJid The account's own JID.
 * @param format The id format.
 */
export function generateMessageId(
    meJid = '',
    format: MessageIdFormat = 'web',
): string {
    return format === 'mobile'
        ? generateMobileMessageId(meJid)
        : generateWebMessageId(meJid)
}

/**
 * Generates a random id for things that are not messages — IQ transaction
 * ids, sync ids and call ids.
 *
 * @param length The number of random bytes.
 */
export function generateRandomId(length = 16): string {
    return toHex(randomBytesOf(length)).toUpperCase()
}
