/**
 * The participant hash (`phash`).
 *
 * Group and broadcast-list fanouts carry a `phash` attribute: a hash over
 * the *canonical* set of participant devices. The receiving client uses it
 * to recognise a fanout it has already processed, and the server uses it to
 * detect a mismatched recipient set.
 *
 * The canonical form of a device JID is `<user>.0:<device>@<server>`, with
 * `c.us` rewritten to `s.whatsapp.net`. The canonical strings are sorted
 * bytewise and hashed as a single SHA-256 stream; the first six bytes are
 * base64 encoded and prefixed with `2:`.
 */

import { sha256 } from '../crypto/primitives.js'
import { HOST_DOMAIN } from './jid.js'

/** The number of digest bytes that end up in the phash. */
const PHASH_DIGEST_PREFIX = 6

/** The character `.`. */
const CHAR_DOT = 0x2e
/** The character `0`. */
const CHAR_ZERO = 0x30
/** The character `:`. */
const CHAR_COLON = 0x3a
/** The character `@`. */
const CHAR_AT = 0x40
/** The character `c`. */
const CHAR_C = 0x63
/** The character `u`. */
const CHAR_U = 0x75
/** The character `s`. */
const CHAR_S = 0x73

/**
 * Computes the v2 participant hash.
 *
 * @param participants The device JIDs, in any order.
 * @returns The `2:`-prefixed phash, or `2:` for an empty list.
 */
export function computePhashV2(participants: readonly string[]): string {
    const n = participants.length
    if (n === 0) return '2:'

    const canonical: Uint8Array[] = new Array(n)
    for (let i = 0; i < n; i += 1) {
        canonical[i] = canonicalizeJid(participants[i]!)
    }
    canonical.sort(compareBytes)

    const digest = sha256(...canonical)
    return `2:${bytesToBase64(digest.subarray(0, PHASH_DIGEST_PREFIX))}`
}

/**
 * Canonicalizes a device JID.
 *
 * @param jid The JID.
 */
function canonicalizeJid(jid: string): Uint8Array {
    const encoder = new TextEncoder()
    const atIndex = jid.indexOf('@')
    if (atIndex < 1 || atIndex >= jid.length - 1) {
        return encoder.encode(jid)
    }
    const colonIndex = jid.indexOf(':', 0)
    const userEnd = colonIndex >= 0 && colonIndex < atIndex ? colonIndex : atIndex
    const hasZeroAgent =
        userEnd >= 2 &&
        jid.charCodeAt(userEnd - 2) === CHAR_DOT &&
        jid.charCodeAt(userEnd - 1) === CHAR_ZERO
    const baseUserEnd = hasZeroAgent ? userEnd - 2 : userEnd

    let device = 0
    if (colonIndex >= 0 && colonIndex < atIndex) {
        for (let i = colonIndex + 1; i < atIndex; i += 1) {
            const digit = jid.charCodeAt(i) - CHAR_ZERO
            if (digit < 0 || digit > 9) {
                device = 0
                break
            }
            device = device * 10 + digit
            if (!Number.isSafeInteger(device)) {
                device = 0
                break
            }
        }
    }

    const serverStart = atIndex + 1
    const serverLength = jid.length - serverStart
    const isCUs =
        serverLength === 4 &&
        jid.charCodeAt(serverStart) === CHAR_C &&
        jid.charCodeAt(serverStart + 1) === CHAR_DOT &&
        jid.charCodeAt(serverStart + 2) === CHAR_U &&
        jid.charCodeAt(serverStart + 3) === CHAR_S

    const parts: string[] = [jid.slice(0, baseUserEnd), '.0:', String(device), '@']
    parts.push(isCUs ? HOST_DOMAIN : jid.slice(serverStart))
    return encoder.encode(parts.join(''))
}

/**
 * Compares two byte arrays lexicographically.
 *
 * @param a The first array.
 * @param b The second array.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const length = a.length < b.length ? a.length : b.length
    for (let i = 0; i < length; i += 1) {
        const diff = a[i]! - b[i]!
        if (diff !== 0) return diff
    }
    return a.length - b.length
}

/**
 * Encodes bytes as standard base64.
 *
 * @param bytes The bytes.
 */
function bytesToBase64(bytes: Uint8Array): string {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64')
}
