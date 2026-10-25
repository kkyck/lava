/**
 * Protobuf codec tests.
 *
 * The codec is the foundation of everything else, so the tests cover the
 * wire types, the field ordering, the nesting and the forward compatibility
 * rules.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { decode, encode, getMessage, schemaStats } from '../src/proto/codec.js'
import '../src/proto/schema.js'

describe('proto codec', () => {
    it('round-trips a scalar string', () => {
        const bytes = encode('Message', { conversation: 'hello world' })
        const decoded = decode('Message', bytes)
        assert.equal(decoded.conversation, 'hello world')
    })

    it('round-trips a nested message', () => {
        const bytes = encode('Message', {
            extendedTextMessage: { text: 'nested', title: 'subject' },
        })
        const decoded = decode('Message', bytes)
        const nested = decoded.extendedTextMessage as Record<string, unknown>
        assert.equal(nested.text, 'nested')
        assert.equal(nested.title, 'subject')
    })

    it('round-trips repeated message fields', () => {
        const bytes = encode('Message', {
            contactsArrayMessage: {
                displayName: 'Alice',
                contacts: [{ displayName: 'A' }, { displayName: 'B' }],
            },
        })
        const decoded = decode('Message', bytes)
        const array = decoded.contactsArrayMessage as Record<string, unknown>
        assert.equal(array.displayName, 'Alice')
        const list = array.contacts as Record<string, unknown>[]
        assert.equal(list.length, 2)
        assert.equal(list[0]!.displayName, 'A')
        assert.equal(list[1]!.displayName, 'B')
    })

    it('round-trips bytes and booleans', () => {
        const payload = new Uint8Array([1, 2, 3, 250])
        const bytes = encode('Message', { documentMessage: { fileName: 'x.bin' } })
        assert.ok(bytes.length > 0)

        const identity = encode('ADVSignedDeviceIdentityHMAC', {
            details: payload,
            hmac: new Uint8Array([9, 9, 9]),
            accountType: 1,
        })
        const decoded = decode('ADVSignedDeviceIdentityHMAC', identity)
        assert.deepEqual(decoded.details, payload)
        assert.deepEqual(decoded.hmac, new Uint8Array([9, 9, 9]))
        assert.equal(decoded.accountType, 1)
    })

    it('encodes fields in ascending field-number order', () => {
        // The object keys are given out of order on purpose: the encoder must
        // sort by the wire field number, not by the insertion order.
        const bytes = encode('Message', {
            extendedTextMessage: { text: 'y' },
            conversation: 'x',
        })
        // The tag byte is `(fieldNumber << 3) | wireType`; both fields are
        // length-delimited, so the wire type is 2.
        assert.equal(bytes[0]! >> 3, 1)
        // Field 1 (`conversation`) is one byte of tag, one of length and one
        // of payload, so the next tag starts at offset 3.
        assert.equal(bytes[3]! >> 3, 6)
    })

    it('ignores unknown fields when decoding', () => {
        const known = encode('Message', { conversation: 'keep' })
        // Append field 500 (varint), which the schema does not know.
        // The tag (500 << 3 | 0) = 4000 needs two varint bytes.
        const extra = new Uint8Array(known.length + 3)
        extra.set(known)
        extra[known.length] = 0xc0
        extra[known.length + 1] = 0x1f
        extra[known.length + 2] = 42
        const decoded = decode('Message', extra)
        assert.equal(decoded.conversation, 'keep')
    })

    it('skips a known field with a mismatched wire type', () => {
        // Field 100 is `botTaskMessage`, a length-delimited message. The
        // server must not be able to break the parser by sending it as a
        // varint, so the field is skipped instead of mis-parsed.
        const known = encode('Message', { conversation: 'keep' })
        const extra = new Uint8Array(known.length + 3)
        extra.set(known)
        extra[known.length] = 0xa0
        extra[known.length + 1] = 0x06
        extra[known.length + 2] = 42
        const decoded = decode('Message', extra)
        assert.equal(decoded.conversation, 'keep')
        assert.equal(decoded.botTaskMessage, undefined)
    })

    it('rejects an unknown message type', () => {
        assert.throws(() => encode('NotARealMessage', {}), /unknown message type/)
        assert.throws(() => decode('NotARealMessage', new Uint8Array(0)), /unknown message type/)
    })

    it('throws on a truncated buffer', () => {
        assert.throws(() => decode('Message', new Uint8Array([0x0a, 0x05])))
    })

    it('exposes the schema registry', () => {
        assert.ok(getMessage('Message'))
        assert.ok(getMessage('ClientPayload'))
        assert.ok(getMessage('ADVSignedDeviceIdentity'))
        assert.equal(getMessage('DoesNotExist'), undefined)
    })

    it('ships a large, complete schema', () => {
        const stats = schemaStats()
        assert.ok(stats.messages > 400, `expected >400 messages, got ${stats.messages}`)
        assert.ok(stats.fields > 2000, `expected >2000 fields, got ${stats.fields}`)
    })
})
