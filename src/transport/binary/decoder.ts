/**
 * The WhatsApp binary-node decoder.
 *
 * Mirrors {@link encodeBinaryNode}: the same token tables in reverse.
 *
 * Node content comes back in the shape it was written:
 *
 * - text content decodes to a `string`,
 * - binary content decodes to a `Uint8Array`,
 * - a child list decodes to a `BinaryNode[]`,
 * - a node without content decodes to `null`.
 */

import { inflateRawSync, unzipSync } from 'node:zlib'
import {
    BINARY_20,
    BINARY_32,
    BINARY_8,
    DICTIONARIES,
    DICTIONARY_0,
    DICTIONARY_3,
    HEX_8,
    HEX_ALPHABET,
    JID_FB,
    JID_INTEROP,
    JID_PAIR,
    JID_U,
    JID_U_DOMAIN_TYPE_HOSTED_LID,
    JID_U_DOMAIN_TYPE_HOSTED_MASK,
    JID_U_DOMAIN_TYPE_LID,
    JID_U_DOMAIN_TYPE_LID_MASK,
    LIST_16,
    LIST_8,
    LIST_EMPTY,
    NIBBLE_8,
    NIBBLE_ALPHABET,
    SINGLE_BYTE_TOKENS,
    STREAM_END,
} from './constants.js'
import type { BinaryNode } from './types.js'
import {
    HOSTED_LID_SERVER,
    HOSTED_SERVER,
    HOST_DOMAIN,
    INTEROP_SERVER,
    LID_SERVER,
    MSGR_SERVER,
} from '../../protocol/jid.js'

/** Encodes strings as UTF-8. */
const TEXT_ENCODER = new TextEncoder()

/** Decodes UTF-8, replacing malformed sequences with `U+FFFD`. */
const TEXT_DECODER = new TextDecoder()

/** Decodes UTF-8 strictly: malformed sequences raise an error. */
const STRICT_TEXT_DECODER = new TextDecoder('utf-8', { fatal: true })

/** A cursor over a byte buffer. */
class ByteReader {
    private offset = 0

    /**
     * @param data The buffer to read from.
     */
    constructor(private readonly data: Uint8Array) {}

    /** Reads one byte. */
    readUint8(): number {
        this.ensure(1)
        const value = this.data[this.offset]!
        this.offset += 1
        return value
    }

    /** Reads a big-endian 16-bit integer. */
    readUint16(): number {
        this.ensure(2)
        const value = (this.data[this.offset]! << 8) | this.data[this.offset + 1]!
        this.offset += 2
        return value
    }

    /** Reads a big-endian 32-bit integer. */
    readUint32(): number {
        this.ensure(4)
        const value =
            (this.data[this.offset]! << 24) |
            (this.data[this.offset + 1]! << 16) |
            (this.data[this.offset + 2]! << 8) |
            this.data[this.offset + 3]!
        this.offset += 4
        return value >>> 0
    }

    /**
     * Reads `length` bytes.
     *
     * @param length The number of bytes.
     */
    readBytes(length: number): Uint8Array {
        this.ensure(length)
        const value = this.data.subarray(this.offset, this.offset + length)
        this.offset += length
        return value
    }

    /** The number of bytes left. */
    getRemaining(): number {
        return this.data.length - this.offset
    }

    /** The current read position. */
    getPosition(): number {
        return this.offset
    }

    /**
     * Moves the read position back to a previously saved one.
     *
     * @param position The position to restore.
     */
    seek(position: number): void {
        this.offset = position
    }

    /**
     * Throws when fewer than `length` bytes remain.
     *
     * @param length The number of bytes needed.
     */
    private ensure(length: number): void {
        if (this.offset + length > this.data.length) {
            throw new Error('unexpected end of binary node payload')
        }
    }
}

/** Cached nibble/hex pair tables, keyed by their alphabet. */
const PACKED_PAIR_TABLES = new WeakMap<readonly string[], string[]>()

/**
 * Builds (and caches) the table that expands one byte into two characters.
 *
 * @param alphabet The packed alphabet.
 */
function packedPairTable(alphabet: readonly string[]): string[] {
    let pairs = PACKED_PAIR_TABLES.get(alphabet)
    if (!pairs) {
        const built = new Array<string>(256)
        for (let i = 0; i < 256; i += 1) {
            built[i] = alphabet[(i >>> 4) & 0x0f]! + alphabet[i & 0x0f]!
        }
        PACKED_PAIR_TABLES.set(alphabet, built)
        pairs = built
    }
    return pairs
}

/**
 * Reads a packed string.
 *
 * @param reader The reader.
 * @param alphabet The packed alphabet.
 */
function parsePacked(reader: ByteReader, alphabet: readonly string[]): string {
    const lengthByte = reader.readUint8()
    const odd = (lengthByte & 0x80) !== 0
    const byteCount = lengthByte & 0x7f
    const outLength = byteCount * 2 - (odd ? 1 : 0)
    if (outLength < 0) {
        throw new Error(`invalid packed length byte 0x${lengthByte.toString(16)}`)
    }
    const pairs = packedPairTable(alphabet)
    let out = ''
    for (let i = 0; i < byteCount; i += 1) out += pairs[reader.readUint8()]!
    return odd ? out.slice(0, outLength) : out
}

/**
 * Reads a length-prefixed byte string.
 *
 * @param reader The reader.
 * @param token The token that introduced the value.
 */
function readBinary(reader: ByteReader, token: number): Uint8Array {
    if (token === BINARY_8) return reader.readBytes(reader.readUint8())
    if (token === BINARY_20) {
        const length =
            ((reader.readUint8() & 0x0f) << 16) | (reader.readUint8() << 8) | reader.readUint8()
        return reader.readBytes(length)
    }
    if (token === BINARY_32) return reader.readBytes(reader.readUint32())
    throw new Error(`invalid binary token ${token}`)
}

/**
 * Decodes a string value.
 *
 * @param token The token that introduced the value.
 * @param reader The reader.
 */
function decodeTokenString(token: number, reader: ByteReader): string {
    if (token > 0 && token <= SINGLE_BYTE_TOKENS.length) {
        return SINGLE_BYTE_TOKENS[token - 1]!
    }
    if (token >= DICTIONARY_0 && token <= DICTIONARY_3) {
        const dictionaryIndex = token - DICTIONARY_0
        const index = reader.readUint8()
        const dictionary = DICTIONARIES[dictionaryIndex]
        if (!dictionary || index >= dictionary.length) {
            throw new Error(`invalid dictionary token ${dictionaryIndex}:${index}`)
        }
        return dictionary[index]!
    }
    if (token === NIBBLE_8) return parsePacked(reader, NIBBLE_ALPHABET)
    if (token === HEX_8) return parsePacked(reader, HEX_ALPHABET)
    if (token === BINARY_8 || token === BINARY_20 || token === BINARY_32) {
        return TEXT_DECODER.decode(readBinary(reader, token))
    }
    throw new Error(`unsupported string token ${token}`)
}

/**
 * Decodes bytes that may hold text.
 *
 * The WAP format has no separate "text blob": a string and a byte string are
 * both written as a length-prefixed blob, so the only way to tell them apart
 * is to look at the bytes themselves. Content that is not valid UTF-8, or that
 * contains control characters, is binary and stays raw bytes.
 *
 * @param bytes The bytes to inspect.
 * @returns The text, or `undefined` when the bytes are not text.
 */
function decodeTextContent(bytes: Uint8Array): string | undefined {
    if (bytes.length === 0) return ''
    let text: string
    try {
        text = STRICT_TEXT_DECODER.decode(bytes)
    } catch {
        return undefined
    }
    for (let i = 0; i < text.length; i += 1) {
        const code = text.charCodeAt(i)
        // C0 controls (except tab, newline and carriage return) and DEL.
        if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return undefined
        if (code === 0x7f) return undefined
        // C1 controls.
        if (code >= 0x80 && code <= 0x9f) return undefined
    }
    return text
}

/**
 * Decodes a `JID_PAIR` value.
 *
 * @param reader The reader.
 */
function decodeJidPair(reader: ByteReader): string {
    const userToken = reader.readUint8()
    const user = userToken === LIST_EMPTY ? '' : decodeTokenString(userToken, reader)
    const serverToken = reader.readUint8()
    const server = serverToken === LIST_EMPTY ? '' : decodeTokenString(serverToken, reader)
    if (!user) return server
    return `${user}@${server}`
}

/**
 * Decodes a `JID_U` value.
 *
 * @param reader The reader.
 */
function decodeJidU(reader: ByteReader): string {
    const domainType = reader.readUint8()
    const device = reader.readUint8()
    const userToken = reader.readUint8()
    const user = userToken === LIST_EMPTY ? '' : decodeTokenString(userToken, reader)
    let domain = HOST_DOMAIN
    if (domainType === JID_U_DOMAIN_TYPE_LID) domain = LID_SERVER
    else if (domainType === JID_U_DOMAIN_TYPE_HOSTED_LID) domain = HOSTED_LID_SERVER
    else if (
        (domainType & JID_U_DOMAIN_TYPE_HOSTED_MASK) !== 0 &&
        (domainType & JID_U_DOMAIN_TYPE_LID_MASK) === 0
    ) {
        domain = HOSTED_SERVER
    }
    if (device > 0) return `${user}:${device}@${domain}`
    return `${user}@${domain}`
}

/**
 * Decodes a `JID_INTEROP` value.
 *
 * The server part is optional: some senders leave it out, so a missing or
 * unreadable string falls back to the `interop` domain.
 *
 * @param reader The reader.
 */
function decodeJidInterop(reader: ByteReader): string {
    const user = decodeTokenString(reader.readUint8(), reader)
    const device = reader.readUint16()
    const integrator = reader.readUint16()
    let server = INTEROP_SERVER
    const serverAt = reader.getPosition()
    try {
        server = decodeTokenString(reader.readUint8(), reader)
    } catch {
        reader.seek(serverAt)
    }
    return `${integrator}-${user}:${device}@${server}`
}

/**
 * Decodes a `JID_FB` value.
 *
 * @param reader The reader.
 */
function decodeJidFb(reader: ByteReader): string {
    const user = decodeTokenString(reader.readUint8(), reader)
    const device = reader.readUint16()
    decodeTokenString(reader.readUint8(), reader)
    return `${user}:${device}@${MSGR_SERVER}`
}

/**
 * Decodes a value.
 *
 * @param reader The reader.
 * @param token The token that introduced the value.
 * @param forAttr `true` when the value is an attribute (always text).
 */
function decodeValue(
    reader: ByteReader,
    token: number,
    forAttr: boolean,
): string | Uint8Array | null {
    if (token === LIST_EMPTY) return null
    if (token === JID_PAIR) return decodeJidPair(reader)
    if (token === JID_U) return decodeJidU(reader)
    if (token === JID_INTEROP) return decodeJidInterop(reader)
    if (token === JID_FB) return decodeJidFb(reader)
    if (token === BINARY_8 || token === BINARY_20 || token === BINARY_32) {
        const binary = readBinary(reader, token)
        return forAttr ? TEXT_DECODER.decode(binary) : binary
    }
    return decodeTokenString(token, reader)
}

/**
 * Decodes the content of a node.
 *
 * @param reader The reader.
 * @param token The token that introduced the content.
 * @returns The content: text, raw bytes, a child list or `null`.
 */
function decodeContentValue(reader: ByteReader, token: number): BinaryNode['content'] {
    if (token === LIST_EMPTY) return null
    if (token === JID_PAIR) return decodeJidPair(reader)
    if (token === JID_U) return decodeJidU(reader)
    if (token === JID_INTEROP) return decodeJidInterop(reader)
    if (token === JID_FB) return decodeJidFb(reader)
    if (token === BINARY_8 || token === BINARY_20 || token === BINARY_32) {
        const bytes = readBinary(reader, token)
        const text = decodeTextContent(bytes)
        return text === undefined ? bytes : text
    }
    return decodeTokenString(token, reader)
}

/**
 * Decodes a node and everything below it.
 *
 * @param reader The reader.
 */
function decodeNodeInternal(reader: ByteReader): BinaryNode {
    const listType = reader.readUint8()
    let listSize = 0
    if (listType === LIST_8) listSize = reader.readUint8()
    else if (listType === LIST_16) listSize = reader.readUint16()
    else throw new Error(`invalid node list type ${listType}`)
    if (listSize === 0) throw new Error('invalid binary node: empty list')

    const tagToken = reader.readUint8()
    const tagValue = decodeValue(reader, tagToken, true)
    if (typeof tagValue !== 'string' || tagValue.length === 0) {
        throw new Error('invalid binary node tag')
    }

    const attrs: Record<string, string> = {}
    let remaining = listSize - 1
    while (remaining > 1) {
        const keyToken = reader.readUint8()
        const key = decodeValue(reader, keyToken, true)
        const valueToken = reader.readUint8()
        const value = decodeValue(reader, valueToken, true)
        if (typeof key !== 'string' || typeof value !== 'string') {
            throw new Error('invalid binary node attribute entry')
        }
        attrs[key] = value
        remaining -= 2
    }

    let content: BinaryNode['content'] = null
    if (remaining === 1) {
        const contentToken = reader.readUint8()
        if (contentToken === LIST_8 || contentToken === LIST_16) {
            const childrenCount = contentToken === LIST_8 ? reader.readUint8() : reader.readUint16()
            const children = new Array<BinaryNode>(childrenCount)
            for (let i = 0; i < childrenCount; i += 1) {
                children[i] = decodeNodeInternal(reader)
            }
            content = children
        } else {
            content = decodeContentValue(reader, contentToken)
        }
    }

    return { tag: tagValue, attrs, content }
}

/**
 * Decodes raw WhatsApp binary node bytes.
 *
 * @param data The encoded node.
 * @returns The decoded node.
 */
export function decodeBinaryNode(data: Uint8Array): BinaryNode {
    return decodeNodeInternal(new ByteReader(data))
}

/**
 * Inflates a compressed stanza body.
 *
 * @param data The compressed bytes.
 */
function inflateCompressedStanza(data: Uint8Array): Uint8Array {
    try {
        return new Uint8Array(unzipSync(data))
    } catch {
        try {
            return new Uint8Array(inflateRawSync(data))
        } catch (rawError) {
            const message = rawError instanceof Error ? rawError.message : String(rawError)
            throw new Error(`failed to inflate compressed stanza: ${message}`)
        }
    }
}

/**
 * Decodes a framed stanza.
 *
 * Reads the one-byte flag the WhatsApp Web socket framing puts in front of
 * the node bytes and parses the rest as a node. The `0x02` flag marks a
 * zlib-compressed body, which is inflated before parsing.
 *
 * @param stanza The framed stanza.
 * @returns The decoded node.
 */
export function decodeBinaryNodeStanza(stanza: Uint8Array): BinaryNode {
    const reader = new ByteReader(stanza)
    const flag = reader.readUint8()
    if (flag === STREAM_END && reader.getRemaining() === 0) {
        throw new Error('stream end stanza is not a binary node')
    }
    let nodeBytes = reader.readBytes(reader.getRemaining())
    if ((flag & 0x02) !== 0) nodeBytes = inflateCompressedStanza(nodeBytes)
    return decodeBinaryNode(nodeBytes)
}
