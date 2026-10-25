/**
 * The WhatsApp binary-node encoder.
 *
 * A node is encoded as a list: `[tag, key₁, value₁, key₂, value₂, …, content?]`.
 * Strings are compressed through the shared token dictionaries whenever
 * possible, JIDs get their own compact encoding, and short numeric strings
 * are packed two characters per byte.
 */

import {
    BINARY_20,
    BINARY_32,
    BINARY_8,
    DICTIONARY_0,
    HEX_8,
    JID_PAIR,
    JID_U,
    JID_U_DOMAIN_TYPE_HOSTED,
    JID_U_DOMAIN_TYPE_HOSTED_LID,
    JID_U_DOMAIN_TYPE_LID,
    JID_U_DOMAIN_TYPE_PN,
    LIST_16,
    LIST_8,
    LIST_EMPTY,
    MERGED_TOKEN_DICTIONARY_FLAG,
    MERGED_TOKEN_MAP,
    NIBBLE_8,
} from './constants.js'
import type { BinaryNode } from './types.js'
import {
    BROADCAST_SERVER,
    BOT_SERVER,
    GROUP_SERVER,
    HOSTED_LID_SERVER,
    HOSTED_SERVER,
    HOST_DOMAIN,
    INTEROP_SERVER,
    LID_SERVER,
    MSGR_SERVER,
    NEWSLETTER_SERVER,
} from '../../protocol/jid.js'

/** Encodes strings as UTF-8. */
const TEXT_ENCODER = new TextEncoder()

/** A growable big-endian byte writer. */
class ByteWriter {
    private buffer: Uint8Array
    private offset = 0

    /**
     * @param initialCapacity The initial buffer size.
     */
    constructor(initialCapacity = 256) {
        this.buffer = new Uint8Array(initialCapacity)
    }

    /** Writes one byte. */
    writeUint8(value: number): void {
        this.ensure(1)
        this.buffer[this.offset] = value & 0xff
        this.offset += 1
    }

    /** Writes a big-endian 16-bit integer. */
    writeUint16(value: number): void {
        this.ensure(2)
        this.buffer[this.offset] = (value >>> 8) & 0xff
        this.buffer[this.offset + 1] = value & 0xff
        this.offset += 2
    }

    /** Writes a big-endian 32-bit integer. */
    writeUint32(value: number): void {
        this.ensure(4)
        this.buffer[this.offset] = (value >>> 24) & 0xff
        this.buffer[this.offset + 1] = (value >>> 16) & 0xff
        this.buffer[this.offset + 2] = (value >>> 8) & 0xff
        this.buffer[this.offset + 3] = value & 0xff
        this.offset += 4
    }

    /** Writes a byte slice. */
    writeBytes(value: Uint8Array): void {
        this.ensure(value.length)
        this.buffer.set(value, this.offset)
        this.offset += value.length
    }

    /** Reserves a single byte and returns its offset, for later patching. */
    reserveUint8(): number {
        this.ensure(1)
        const at = this.offset
        this.offset += 1
        return at
    }

    /**
     * Patches a previously reserved byte.
     *
     * @param at The offset returned by {@link reserveUint8}.
     * @param value The value to write.
     */
    patchUint8(at: number, value: number): void {
        this.buffer[at] = value & 0xff
    }

    /**
     * Writes the UTF-8 encoding of a string.
     *
     * @param value The string.
     * @param maxBytes The maximum number of bytes to write.
     * @returns The number of bytes written.
     */
    writeUtf8(value: string, maxBytes: number): number {
        this.ensure(maxBytes)
        const result = TEXT_ENCODER.encodeInto(value, this.buffer.subarray(this.offset))
        this.offset += result.written
        return result.written
    }

    /** Returns the written bytes. */
    toUint8Array(): Uint8Array {
        return this.buffer.subarray(0, this.offset)
    }

    /** Grows the buffer so that `extra` more bytes fit. */
    private ensure(extra: number): void {
        const needed = this.offset + extra
        if (needed <= this.buffer.length) return
        let size = this.buffer.length
        while (size < needed) size *= 2
        const next = new Uint8Array(size)
        next.set(this.buffer)
        this.buffer = next
    }
}

/** The value is written as a plain UTF-8 string. */
const PACKED_NONE = 0
/** The value is written two characters per byte. */
const PACKED_NIBBLE = 1
/** The value is written two hex characters per byte. */
const PACKED_HEX = 2

/**
 * Decides how a string can be packed most efficiently.
 *
 * @param value The string to classify.
 */
function classifyPackedString(value: string): number {
    const n = value.length
    if (n === 0 || n >= 128) return PACKED_NONE
    let nibbleOk = true
    let hexOk = true
    for (let i = 0; i < n; i += 1) {
        const code = value.charCodeAt(i)
        if (code >= 48 && code <= 57) continue
        if (code === 45 || code === 46) {
            // `-` and `.` only exist in the nibble alphabet.
            hexOk = false
            if (!nibbleOk) return PACKED_NONE
            continue
        }
        if (code >= 65 && code <= 70) {
            // `A`-`F` only exist in the hex alphabet.
            nibbleOk = false
            if (!hexOk) return PACKED_NONE
            continue
        }
        return PACKED_NONE
    }
    return nibbleOk ? PACKED_NIBBLE : PACKED_HEX
}

/**
 * Maps a character to its nibble value.
 *
 * @param value The string.
 * @param index The character index.
 * @param packedType The packed format in use.
 */
function toNibble(value: string, index: number, packedType: number): number {
    const code = value.charCodeAt(index)
    if (code >= 48 && code <= 57) return code - 48
    if (packedType === NIBBLE_8) {
        if (code === 45) return 10
        if (code === 46) return 11
    }
    if (packedType === HEX_8 && code >= 65 && code <= 70) return code - 55
    throw new Error(`cannot nibble encode char code ${code}`)
}

/**
 * Writes a packed string.
 *
 * @param value The string.
 * @param packedType The packed format token.
 * @param writer The writer.
 */
function writePackedString(value: string, packedType: number, writer: ByteWriter): void {
    const odd = value.length % 2 === 1
    writer.writeUint8(packedType)
    let length = Math.ceil(value.length / 2)
    if (odd) length |= 0x80
    writer.writeUint8(length)
    for (let i = 0; i < value.length; i += 2) {
        const high = toNibble(value, i, packedType)
        let low = 0x0f
        if (i + 1 < value.length) low = toNibble(value, i + 1, packedType)
        writer.writeUint8((high << 4) | low)
    }
}

/**
 * Writes a length-prefixed byte string.
 *
 * @param length The byte length.
 * @param writer The writer.
 */
function writeBinaryLength(length: number, writer: ByteWriter): void {
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error(`invalid binary length ${length}`)
    }
    if (length < 256) {
        writer.writeUint8(BINARY_8)
        writer.writeUint8(length)
        return
    }
    if (length < 1 << 20) {
        writer.writeUint8(BINARY_20)
        writer.writeUint8((length >>> 16) & 0xff)
        writer.writeUint8((length >>> 8) & 0xff)
        writer.writeUint8(length & 0xff)
        return
    }
    if (length >= 4294967296) {
        throw new Error(`binary with length ${length} is too big for the WAP protocol`)
    }
    writer.writeUint8(BINARY_32)
    writer.writeUint32(length)
}

/**
 * Writes a UTF-8 string with its length prefix.
 *
 * @param value The string.
 * @param writer The writer.
 */
function writeUtf8WithLength(value: string, writer: ByteWriter): void {
    if (value.length < 86) {
        writer.writeUint8(BINARY_8)
        const lengthAt = writer.reserveUint8()
        const written = writer.writeUtf8(value, value.length * 3)
        writer.patchUint8(lengthAt, written)
        return
    }
    const encoded = TEXT_ENCODER.encode(value)
    writeBinaryLength(encoded.length, writer)
    writer.writeBytes(encoded)
}

/**
 * Writes a string, using the token dictionary when possible.
 *
 * @param value The string.
 * @param writer The writer.
 */
function writeString(value: string, writer: ByteWriter): void {
    const token = MERGED_TOKEN_MAP.get(value)
    if (token !== undefined) {
        if (token < MERGED_TOKEN_DICTIONARY_FLAG) {
            writer.writeUint8(token)
        } else {
            writer.writeUint8(DICTIONARY_0 + ((token >>> 8) & 0xff))
            writer.writeUint8(token & 0xff)
        }
        return
    }
    const packed = classifyPackedString(value)
    if (packed === PACKED_NIBBLE) {
        writePackedString(value, NIBBLE_8, writer)
        return
    }
    if (packed === PACKED_HEX) {
        writePackedString(value, HEX_8, writer)
        return
    }
    writeUtf8WithLength(value, writer)
}

/**
 * The servers the codec recognises.
 *
 * A JID whose server is on this list gets a compact encoding; every other
 * server still travels as a `JID_PAIR`, but without a domain type.
 */
const KNOWN_JID_SERVERS: readonly string[] = Object.freeze([
    HOST_DOMAIN,
    LID_SERVER,
    GROUP_SERVER,
    NEWSLETTER_SERVER,
    BROADCAST_SERVER,
    HOSTED_LID_SERVER,
    HOSTED_SERVER,
    BOT_SERVER,
    MSGR_SERVER,
    INTEROP_SERVER,
])

/** Marks a server that has no `JID_U` domain type. */
const NO_JID_U_DOMAIN = -1

/**
 * Returns the domain type the `JID_U` token uses for a server.
 *
 * @param server The server segment of a JID.
 * @returns The domain type, or {@link NO_JID_U_DOMAIN} when the server has none.
 */
function jidDomainType(server: string): number {
    if (server === HOST_DOMAIN) return JID_U_DOMAIN_TYPE_PN
    if (server === LID_SERVER) return JID_U_DOMAIN_TYPE_LID
    if (server === HOSTED_SERVER) return JID_U_DOMAIN_TYPE_HOSTED
    if (server === HOSTED_LID_SERVER) return JID_U_DOMAIN_TYPE_HOSTED_LID
    return NO_JID_U_DOMAIN
}

/**
 * Returns the server segment of a JID.
 *
 * Known servers are returned from the interned list, so no string is
 * allocated for the common case.
 *
 * @param value The JID.
 * @param from The offset of the server segment.
 */
function jidServerAt(value: string, from: number): string {
    const length = value.length - from
    for (let i = 0; i < KNOWN_JID_SERVERS.length; i += 1) {
        const server = KNOWN_JID_SERVERS[i]!
        if (server.length === length && value.startsWith(server, from)) return server
    }
    return value.slice(from)
}

/**
 * Writes a JID in its compact form.
 *
 * A JID that carries a device id on a server with a domain type uses the
 * `JID_U` token; everything else uses the `JID_PAIR` token, which keeps the
 * user and the server apart.
 *
 * @param value The JID.
 * @param writer The writer.
 * @returns `true` when the value was written as a JID.
 */
function tryWriteJid(value: string, writer: ByteWriter): boolean {
    const atIndex = value.indexOf('@')
    if (atIndex <= 0 || atIndex === value.length - 1) return false
    if (value.indexOf('@', atIndex + 1) !== -1) return false

    const server = jidServerAt(value, atIndex + 1)
    const domainType = jidDomainType(server)

    // Only the servers that carry a domain type split the `:device` suffix
    // off the user part. For every other server the colon belongs to the
    // user, exactly like WhatsApp Web treats it.
    let userEnd = atIndex
    let device = 0
    if (domainType !== NO_JID_U_DOMAIN) {
        const colonIndex = value.indexOf(':')
        if (colonIndex !== -1 && colonIndex < atIndex) {
            if (colonIndex === atIndex - 1) return false
            for (let i = colonIndex + 1; i < atIndex; i += 1) {
                const digit = value.charCodeAt(i) - 48
                if (digit < 0 || digit > 9) return false
                device = device * 10 + digit
                if (device > 255) return false
            }
            userEnd = colonIndex
        }
    }

    if (domainType !== NO_JID_U_DOMAIN && device !== 0 && userEnd > 0) {
        writer.writeUint8(JID_U)
        writer.writeUint8(domainType)
        writer.writeUint8(device)
        writeString(value.slice(0, userEnd), writer)
        return true
    }

    writer.writeUint8(JID_PAIR)
    if (userEnd === 0) writer.writeUint8(LIST_EMPTY)
    else writeString(value.slice(0, userEnd), writer)
    writeString(server, writer)
    return true
}

/**
 * Writes the size of a list.
 *
 * @param size The element count.
 * @param writer The writer.
 */
function writeListSize(size: number, writer: ByteWriter): void {
    if (!Number.isSafeInteger(size) || size < 0) {
        throw new Error(`invalid list size ${size}`)
    }
    if (size < 256) {
        writer.writeUint8(LIST_8)
        writer.writeUint8(size)
        return
    }
    if (size >= 1 << 16) {
        throw new Error(`list with size ${size} is too large for the WAP protocol`)
    }
    writer.writeUint8(LIST_16)
    writer.writeUint16(size)
}

/**
 * Encodes a node and everything below it.
 *
 * @param node The node.
 * @param writer The writer.
 */
function writeNodeInternal(node: BinaryNode, writer: ByteWriter): void {
    const keys = Object.keys(node.attrs)
    const attrsLen = keys.length
    const hasContent = node.content !== null && node.content !== undefined
    const listSize = 1 + attrsLen * 2 + (hasContent ? 1 : 0)
    writeListSize(listSize, writer)
    writeString(node.tag, writer)
    for (let i = 0; i < keys.length; i += 1) {
        const key = keys[i]!
        writeString(key, writer)
        const value = node.attrs[key] ?? ''
        if (!tryWriteJid(value, writer)) writeString(value, writer)
    }
    if (!hasContent) return

    const content = node.content
    if (content === null || content === undefined) return
    if (typeof content === 'string') {
        // Text content uses the same token compression as attributes, so the
        // decoder can hand it back as a string.
        writeString(content, writer)
        return
    }
    if (content instanceof Uint8Array) {
        writeBinaryLength(content.length, writer)
        writer.writeBytes(content)
        return
    }
    writeListSize(content.length, writer)
    for (const child of content) writeNodeInternal(child, writer)
}

/**
 * Encodes a node into its raw WhatsApp binary representation.
 *
 * @param node The node to encode.
 */
export function encodeBinaryNode(node: BinaryNode): Uint8Array {
    const writer = new ByteWriter()
    writeNodeInternal(node, writer)
    return writer.toUint8Array()
}

/**
 * Encodes a node as a transport stanza.
 *
 * The WhatsApp Web socket framing prefixes the node bytes with a one-byte
 * flag (`0x00`).
 *
 * @param node The node to encode.
 */
export function encodeBinaryNodeStanza(node: BinaryNode): Uint8Array {
    const writer = new ByteWriter()
    writer.writeUint8(0x00)
    writeNodeInternal(node, writer)
    return writer.toUint8Array()
}
