/**
 * The protobuf schema registry.
 *
 * The registry maps a message name to its field descriptors. It lives in its
 * own module so that the generated schema can populate it *without* creating
 * a circular import: `schema.ts` only depends on this module, and
 * `codec.ts` imports the schema at the end.
 */

/** The set of value shapes a field can hold. */
export type FieldType =
    | 'int32'
    | 'int64'
    | 'uint32'
    | 'uint64'
    | 'sint32'
    | 'sint64'
    | 'bool'
    | 'enum'
    | 'fixed32'
    | 'fixed64'
    | 'sfixed32'
    | 'sfixed64'
    | 'float'
    | 'double'
    | 'string'
    | 'bytes'
    | 'message'

/** A single field descriptor. */
export interface FieldDescriptor {
    /** Protobuf field number (1-based). */
    number: number
    /** Object key used in the decoded object (camelCase). */
    name: string
    /** Value shape. */
    type: FieldType
    /** For `message` fields, the name of the nested message type. */
    message?: string
    /** For repeated fields, the element shape. */
    repeated?: boolean
}

/** A message type: a name plus its field descriptors. */
export interface MessageDescriptor {
    /** Fully qualified message name, e.g. `Message`. */
    name: string
    /** Field descriptors indexed by protobuf field number. */
    fields: Map<number, FieldDescriptor>
}

/**
 * The live registry of message descriptors.
 *
 * Exposed so the codec can look up nested message types without importing
 * the registry module twice.
 */
export const registry = new Map<string, MessageDescriptor>()

/**
 * Registers a message descriptor.
 *
 * @param name Message name, used as the key for nested lookups.
 * @param fields Field descriptors. The array index is ignored; only the
 *   `number` property matters.
 */
export function defineMessage(name: string, fields: FieldDescriptor[]): MessageDescriptor {
    const byNumber = new Map<number, FieldDescriptor>()
    for (const field of fields) {
        byNumber.set(field.number, field)
    }
    const descriptor: MessageDescriptor = { name, fields: byNumber }
    registry.set(name, descriptor)
    return descriptor
}

/** Looks up a registered message descriptor. */
export function getMessage(name: string): MessageDescriptor | undefined {
    return registry.get(name)
}

/** Statistics about the registered schema. */
export interface SchemaStats {
    /** The number of registered messages. */
    messages: number
    /** The total number of declared fields. */
    fields: number
}

/**
 * Returns statistics about the registered schema.
 *
 * Useful to assert that the schema was generated and loaded completely.
 */
export function schemaStats(): SchemaStats {
    let fields = 0
    for (const descriptor of registry.values()) fields += descriptor.fields.size
    return { messages: registry.size, fields }
}
