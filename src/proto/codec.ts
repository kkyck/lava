/**
 * A compact, schema-driven protobuf codec.
 *
 * Why not `protobufjs`? That library pulls in ~250 KB of runtime code and
 * builds a large reflection model per message type, which dominates the memory
 * footprint of a WhatsApp client. This implementation instead compiles each
 * message into a flat field descriptor table at module load time and encodes
 * directly against the wire format, allocating only the output buffer.
 *
 * The wire format implemented here is standard protobuf (proto3 semantics):
 *
 * | Wire type | Meaning      | Encoding                          |
 * | --------- | ------------ | --------------------------------- |
 * | 0         | Varint       | LEB128 base-128                   |
 * | 1         | 64-bit       | little-endian                     |
 * | 2         | Length-delim | varint length + payload           |
 * | 5         | 32-bit       | little-endian                     |
 *
 * Unknown fields are skipped, so the codec stays forward compatible with new
 * WhatsApp proto revisions without needing an update.
 */

import {
    defineMessage,
    getMessage,
    registry,
    schemaStats,
    type FieldDescriptor,
    type FieldType,
    type MessageDescriptor,
} from './registry.js'
// Importing the generated schema populates the registry, so every message
// type is available as soon as this module is loaded.
import './schema.js'

export { defineMessage, getMessage, schemaStats } from './registry.js'
export type {
    FieldDescriptor,
    FieldType,
    MessageDescriptor,
    SchemaStats,
} from './registry.js'

/** Protobuf wire types. */
export const WIRE_VARINT = 0
export const WIRE_64BIT = 1
export const WIRE_LENGTH = 2
export const WIRE_32BIT = 5

/** A decoded message: field number to value. */
export type DecodedMessage = Map<number, unknown>

/** Values accepted by the encoder for a field. */
export type FieldValue =
    | number
    | bigint
    | boolean
    | string
    | Uint8Array
    | DecodedMessage
    | null
    | undefined

// ─── Writer ───────────────────────────────────────────────────────────────────

/**
 * A growable protobuf writer.
 *
 * Starts with a small buffer and doubles as needed. `Uint8Array` is used
 * directly (not `Buffer`) so no pooled slab is retained.
 */
export class ProtoWriter {
    private buffer: Uint8Array
    private offset = 0

    constructor(initialCapacity = 256) {
        this.buffer = new Uint8Array(initialCapacity)
    }

    /** Current number of bytes written. */
    get length(): number {
        return this.offset
    }

    /** Writes a base-128 varint. */
    writeVarint(value: bigint | number): this {
        let v = typeof value === 'bigint' ? value : BigInt(Math.trunc(value))
        if (v < 0n) v += 1n << 64n
        do {
            let byte = Number(v & 0x7fn)
            v >>= 7n
            if (v > 0n) byte |= 0x80
            this.ensure(1)
            this.buffer[this.offset++] = byte
        } while (v > 0n)
        return this
    }

    /** Writes a tag (field number + wire type). */
    writeTag(fieldNumber: number, wireType: number): this {
        return this.writeVarint(BigInt((fieldNumber << 3) | wireType))
    }

    /** Writes a length-delimited payload. */
    writeBytes(payload: Uint8Array): this {
        this.writeVarint(payload.length)
        this.ensure(payload.length)
        this.buffer.set(payload, this.offset)
        this.offset += payload.length
        return this
    }

    /** Writes a fixed 32-bit little-endian value. */
    writeFixed32(value: number): this {
        this.ensure(4)
        this.buffer[this.offset++] = value & 0xff
        this.buffer[this.offset++] = (value >>> 8) & 0xff
        this.buffer[this.offset++] = (value >>> 16) & 0xff
        this.buffer[this.offset++] = (value >>> 24) & 0xff
        return this
    }

    /** Writes a fixed 64-bit little-endian value. */
    writeFixed64(value: bigint): this {
        let v = value
        this.ensure(8)
        for (let i = 0; i < 8; i++) {
            this.buffer[this.offset++] = Number(v & 0xffn)
            v >>= 8n
        }
        return this
    }

    /** Writes a 32-bit float. */
    writeFloat(value: number): this {
        const scratch = new DataView(new ArrayBuffer(4))
        scratch.setFloat32(0, value, true)
        this.ensure(4)
        for (let i = 0; i < 4; i++) this.buffer[this.offset++] = scratch.getUint8(i)
        return this
    }

    /** Writes a 64-bit float. */
    writeDouble(value: number): this {
        const scratch = new DataView(new ArrayBuffer(8))
        scratch.setFloat64(0, value, true)
        this.ensure(8)
        for (let i = 0; i < 8; i++) this.buffer[this.offset++] = scratch.getUint8(i)
        return this
    }

    /** Writes a length-prefixed UTF-8 string. */
    writeString(value: string): this {
        return this.writeBytes(new TextEncoder().encode(value))
    }

    /** Returns the encoded bytes. The buffer is copied out to avoid aliasing. */
    finish(): Uint8Array {
        return this.buffer.slice(0, this.offset)
    }

    private ensure(extra: number): void {
        const needed = this.offset + extra
        if (needed <= this.buffer.length) return
        let size = this.buffer.length
        while (size < needed) size *= 2
        const next = new Uint8Array(size)
        next.set(this.buffer.subarray(0, this.offset))
        this.buffer = next
    }
}

// ─── Reader ───────────────────────────────────────────────────────────────────

/**
 * A protobuf reader over a byte range.
 *
 * The reader never copies the source buffer; decoded `bytes` fields are
 * subarray views, which keeps large media payloads allocation-free.
 */
export class ProtoReader {
    private offset: number

    constructor(
        private readonly data: Uint8Array,
        start = 0,
        end = data.length,
    ) {
        this.offset = start
        this.end = end
    }

    /** Exclusive end offset. */
    readonly end: number

    /** Current read position. */
    get position(): number {
        return this.offset
    }

    /** True when the reader has consumed the whole range. */
    get done(): boolean {
        return this.offset >= this.end
    }

    /** Reads a base-128 varint. */
    readVarint(): bigint {
        let result = 0n
        let shift = 0n
        for (;;) {
            if (this.offset >= this.end) throw new Error('proto: unexpected end of buffer')
            const byte = this.data[this.offset++]!
            result |= BigInt(byte & 0x7f) << shift
            if ((byte & 0x80) === 0) break
            shift += 7n
            if (shift > 63n) throw new Error('proto: varint overflow')
        }
        return result
    }

    /** Reads a signed varint as a `bigint`. */
    readVarintSigned(): bigint {
        const raw = this.readVarint()
        return raw >= 1n << 63n ? raw - (1n << 64n) : raw
    }

    /** Reads a tag; returns the field number and wire type. */
    readTag(): { field: number; wire: number } {
        const tag = this.readVarint()
        return { field: Number(tag >> 3n), wire: Number(tag & 7n) }
    }

    /** Reads a length-delimited payload as a view into the source buffer. */
    readBytes(): Uint8Array {
        const length = Number(this.readVarint())
        if (this.offset + length > this.end) {
            throw new Error('proto: length-delimited field exceeds buffer')
        }
        const view = this.data.subarray(this.offset, this.offset + length)
        this.offset += length
        return view
    }

    /** Reads a length-delimited payload as a UTF-8 string. */
    readString(): string {
        const length = Number(this.readVarint())
        if (this.offset + length > this.end) {
            throw new Error('proto: length-delimited field exceeds buffer')
        }
        const text = decoder.decode(this.data.subarray(this.offset, this.offset + length))
        this.offset += length
        return text
    }

    /** Reads a fixed 32-bit little-endian value. */
    readFixed32(): number {
        this.require(4)
        const value =
            this.data[this.offset]! |
            (this.data[this.offset + 1]! << 8) |
            (this.data[this.offset + 2]! << 16) |
            (this.data[this.offset + 3]! << 24)
        this.offset += 4
        return value >>> 0
    }

    /** Reads a fixed 64-bit little-endian value. */
    readFixed64(): bigint {
        this.require(8)
        let value = 0n
        for (let i = 0; i < 8; i++) {
            value |= BigInt(this.data[this.offset + i]!) << BigInt(i * 8)
        }
        this.offset += 8
        return value
    }

    /** Reads a 32-bit float. */
    readFloat(): number {
        this.require(4)
        const view = new DataView(this.data.buffer, this.data.byteOffset + this.offset, 4)
        this.offset += 4
        return view.getFloat32(0, true)
    }

    /** Reads a 64-bit float. */
    readDouble(): number {
        this.require(8)
        const view = new DataView(this.data.buffer, this.data.byteOffset + this.offset, 8)
        this.offset += 8
        return view.getFloat64(0, true)
    }

    /** Skips a field of the given wire type. */
    skip(wire: number): void {
        switch (wire) {
            case WIRE_VARINT:
                this.readVarint()
                break
            case WIRE_64BIT:
                this.require(8)
                this.offset += 8
                break
            case WIRE_LENGTH: {
                const length = Number(this.readVarint())
                this.require(length)
                this.offset += length
                break
            }
            case WIRE_32BIT:
                this.require(4)
                this.offset += 4
                break
            default:
                throw new Error(`proto: unsupported wire type ${wire}`)
        }
    }

    private require(length: number): void {
        if (this.offset + length > this.end) {
            throw new Error('proto: unexpected end of buffer')
        }
    }
}

const decoder = new TextDecoder()

// ─── High-level encode / decode ──────────────────────────────────────────────

/**
 * Encodes a plain object into protobuf bytes using a registered descriptor.
 *
 * @param typeName Registered message name.
 * @param value Object whose keys are field names.
 */
export function encode(typeName: string, value: Record<string, unknown>): Uint8Array {
    const descriptor = registry.get(typeName)
    if (!descriptor) throw new Error(`proto: unknown message type ${typeName}`)
    const writer = new ProtoWriter()
    encodeInto(writer, descriptor, value)
    return writer.finish()
}

/**
 * Decodes protobuf bytes into a plain object using a registered descriptor.
 *
 * Unknown fields are ignored, keeping the decoder forward compatible.
 */
export function decode(typeName: string, data: Uint8Array): Record<string, unknown> {
    const descriptor = registry.get(typeName)
    if (!descriptor) throw new Error(`proto: unknown message type ${typeName}`)
    const reader = new ProtoReader(data)
    const result: Record<string, unknown> = {}
    while (!reader.done) {
        const { field, wire } = reader.readTag()
        const fieldDescriptor = descriptor.fields.get(field)
        if (!fieldDescriptor) {
            reader.skip(wire)
            continue
        }
        readField(reader, fieldDescriptor, wire, result)
    }
    return result
}

/**
 * Encodes a nested message field into the writer.
 *
 * Fields are written in ascending field-number order, as the protobuf
 * specification requires. The descriptor's field map is built in that order
 * already, so iterating over it is both correct and cheap.
 */
function encodeInto(
    writer: ProtoWriter,
    descriptor: MessageDescriptor,
    value: Record<string, unknown>,
): void {
    for (const field of descriptor.fields.values()) {
        const name = fieldName(field)
        const raw = value[name]
        if (raw === undefined || raw === null) continue
        if (field.repeated) {
            const items = Array.isArray(raw) ? raw : [raw]
            for (const item of items) {
                if (item === undefined || item === null) continue
                writeSingle(writer, field, item)
            }
        } else {
            writeSingle(writer, field, raw)
        }
    }
}

/** Finds a field descriptor by its object key. */
function findFieldByName(descriptor: MessageDescriptor, name: string): FieldDescriptor | undefined {
    for (const field of descriptor.fields.values()) {
        if (fieldName(field) === name) return field
    }
    return undefined
}

/**
 * The object key for a field.
 *
 * Descriptors carry an explicit `name`, so this is a direct lookup.
 */
function fieldName(field: FieldDescriptor): string {
    return field.name
}

/** Writes one value for a field, including the tag. */
function writeSingle(writer: ProtoWriter, field: FieldDescriptor, raw: unknown): void {
    switch (field.type) {
        case 'message': {
            const nested = registry.get(field.message!)
            if (!nested) throw new Error(`proto: unknown nested message ${field.message}`)
            const child = new ProtoWriter()
            encodeInto(child, nested, raw as Record<string, unknown>)
            writer.writeTag(field.number, WIRE_LENGTH)
            writer.writeBytes(child.finish())
            break
        }
        case 'string':
            writer.writeTag(field.number, WIRE_LENGTH)
            writer.writeString(String(raw))
            break
        case 'bytes':
            writer.writeTag(field.number, WIRE_LENGTH)
            writer.writeBytes(raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayLike<number>))
            break
        case 'bool':
            writer.writeTag(field.number, WIRE_VARINT)
            writer.writeVarint(raw ? 1 : 0)
            break
        case 'enum':
        case 'int32':
        case 'int64':
        case 'uint32':
        case 'uint64':
            writer.writeTag(field.number, WIRE_VARINT)
            writer.writeVarint(typeof raw === 'bigint' ? raw : BigInt(Math.trunc(raw as number)))
            break
        case 'sint32':
        case 'sint64':
            writer.writeTag(field.number, WIRE_VARINT)
            writer.writeVarint(zigzag(raw as number | bigint))
            break
        case 'fixed32':
            writer.writeTag(field.number, WIRE_32BIT)
            writer.writeFixed32(raw as number)
            break
        case 'sfixed32':
            writer.writeTag(field.number, WIRE_32BIT)
            writer.writeFixed32(raw as number)
            break
        case 'fixed64':
        case 'sfixed64':
            writer.writeTag(field.number, WIRE_64BIT)
            writer.writeFixed64(typeof raw === 'bigint' ? raw : BigInt(raw as number))
            break
        case 'float':
            writer.writeTag(field.number, WIRE_32BIT)
            writer.writeFloat(raw as number)
            break
        case 'double':
            writer.writeTag(field.number, WIRE_64BIT)
            writer.writeDouble(raw as number)
            break
    }
}

/**
 * Returns the wire type a field type is encoded with.
 *
 * Returns `-1` for types that have no fixed wire type.
 */
function expectedWireType(type: FieldType): number {
    switch (type) {
        case 'int32':
        case 'int64':
        case 'uint32':
        case 'uint64':
        case 'sint32':
        case 'sint64':
        case 'bool':
        case 'enum':
            return WIRE_VARINT
        case 'fixed32':
        case 'sfixed32':
        case 'float':
            return WIRE_32BIT
        case 'fixed64':
        case 'sfixed64':
        case 'double':
            return WIRE_64BIT
        case 'string':
        case 'bytes':
        case 'message':
            return WIRE_LENGTH
        default:
            return -1
    }
}

/**
 * Returns whether a wire type is compatible with a field type.
 *
 * The varint family is interchangeable on the wire, so an `int32` field also
 * accepts the encoding of an `enum` and vice versa.
 */
function wireTypeMatches(type: FieldType, wire: number): boolean {
    const expected = expectedWireType(type)
    if (expected === -1) return true
    if (expected === wire) return true
    return expected === WIRE_VARINT && wire === WIRE_VARINT
}

/** Reads one field into the result object. */
function readField(
    reader: ProtoReader,
    field: FieldDescriptor,
    wire: number,
    result: Record<string, unknown>,
): void {
    const name = fieldName(field)
    // A field whose wire type does not match the schema is treated as an
    // unknown field and skipped. This keeps the decoder forward compatible
    // with a server that reuses a field number for a different type.
    if (!wireTypeMatches(field.type, wire)) {
        reader.skip(wire)
        return
    }
    switch (field.type) {
        case 'message': {
            const bytes = reader.readBytes()
            const nested = registry.get(field.message!)
            if (!nested) {
                reader.skip(wire)
                return
            }
            const value = decodeWith(nested, bytes)
            if (field.repeated) {
                const list = (result[name] as unknown[]) ?? []
                list.push(value)
                result[name] = list
            } else {
                result[name] = value
            }
            break
        }
        case 'string': {
            const value = reader.readString()
            assign(result, name, field, value)
            break
        }
        case 'bytes': {
            const value = reader.readBytes()
            assign(result, name, field, value)
            break
        }
        case 'bool':
            assign(result, name, field, reader.readVarint() !== 0n)
            break
        case 'enum':
        case 'int32':
        case 'int64':
        case 'uint32':
        case 'uint64': {
            const value = reader.readVarintSigned()
            assign(result, name, field, typeof value === 'bigint' && value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER ? Number(value) : value)
            break
        }
        case 'sint32':
        case 'sint64': {
            const value = zigzagDecode(reader.readVarint())
            assign(result, name, field, value)
            break
        }
        case 'fixed32':
        case 'sfixed32':
            assign(result, name, field, reader.readFixed32())
            break
        case 'fixed64':
        case 'sfixed64':
            assign(result, name, field, reader.readFixed64())
            break
        case 'float':
            assign(result, name, field, reader.readFloat())
            break
        case 'double':
            assign(result, name, field, reader.readDouble())
            break
        default:
            reader.skip(wire)
    }
}

/** Assigns a decoded value, honouring repeated fields. */
function assign(result: Record<string, unknown>, name: string, field: FieldDescriptor, value: unknown): void {
    if (field.repeated) {
        const list = (result[name] as unknown[]) ?? []
        list.push(value)
        result[name] = list
    } else {
        result[name] = value
    }
}

/** Decodes using an explicit descriptor (avoids a registry lookup). */
function decodeWith(descriptor: MessageDescriptor, data: Uint8Array): Record<string, unknown> {
    const reader = new ProtoReader(data)
    const result: Record<string, unknown> = {}
    while (!reader.done) {
        const { field, wire } = reader.readTag()
        const fieldDescriptor = descriptor.fields.get(field)
        if (!fieldDescriptor) {
            reader.skip(wire)
            continue
        }
        readField(reader, fieldDescriptor, wire, result)
    }
    return result
}

/** Zig-zag encodes a signed integer. */
function zigzag(value: number | bigint): bigint {
    const v = typeof value === 'bigint' ? value : BigInt(Math.trunc(value))
    return v >= 0n ? v << 1n : ((-v << 1n) - 1n)
}

/** Zig-zag decodes a signed integer. */
function zigzagDecode(value: bigint): number | bigint {
    const decoded = (value >> 1n) ^ -(value & 1n)
    return decoded >= Number.MIN_SAFE_INTEGER && decoded <= Number.MAX_SAFE_INTEGER ? Number(decoded) : decoded
}
