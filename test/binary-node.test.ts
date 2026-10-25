/**
 * Binary node codec tests.
 *
 * The binary codec is what actually goes on the wire, so the tests check the
 * token encoding, the attribute encoding and the round-trip behaviour.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    decodeBinaryNode,
    decodeBinaryNodeStanza,
    encodeBinaryNode,
    encodeBinaryNodeStanza,
} from '../src/transport/binary/codec.js'
import type { BinaryNode } from '../src/transport/binary/types.js'
import { encodeBinaryNodeStanza as encodeStanzaDirect } from '../src/transport/binary/encoder.js'
import { decodeBinaryNodeStanza as decodeStanzaDirect } from '../src/transport/binary/decoder.js'

const SAMPLE: BinaryNode = {
    tag: 'message',
    attrs: {
        to: '1234567890@s.whatsapp.net',
        type: 'text',
        id: '3EB0A1B2C3D4E5F6071',
    },
    content: [
        {
            tag: 'participants',
            attrs: {},
            content: [
                {
                    tag: 'to',
                    attrs: { jid: '1234567890:0@s.whatsapp.net' },
                    content: [
                        {
                            tag: 'enc',
                            attrs: { v: '2', type: 'msg' },
                            content: new Uint8Array([1, 2, 3, 4, 5]),
                        },
                    ],
                },
            ],
        },
    ],
}

describe('binary node codec', () => {
    it('round-trips a message node', () => {
        const bytes = encodeBinaryNode(SAMPLE)
        const decoded = decodeBinaryNode(bytes)
        assert.equal(decoded.tag, 'message')
        assert.equal(decoded.attrs.to, '1234567890@s.whatsapp.net')
        assert.equal(decoded.attrs.id, '3EB0A1B2C3D4E5F6071')
        assert.ok(Array.isArray(decoded.content))
        assert.equal(decoded.content.length, 1)
    })

    it('round-trips a stanza with its flag prefix', () => {
        const bytes = encodeBinaryNodeStanza(SAMPLE)
        assert.equal(bytes[0], 0x00)
        const decoded = decodeBinaryNodeStanza(bytes)
        assert.equal(decoded.tag, 'message')
    })

    it('rejects a stream-end stanza', () => {
        // The reference decoder throws when the frame is the stream-end
        // marker with no body; other flag values are legal because `0x02`
        // marks a compressed stanza.
        assert.throws(() => decodeBinaryNodeStanza(new Uint8Array([0x02])))
    })

    it('exposes the same encoder through both modules', () => {
        assert.deepEqual(
            encodeBinaryNodeStanza(SAMPLE),
            encodeStanzaDirect(SAMPLE),
        )
        assert.deepEqual(
            decodeBinaryNodeStanza(encodeStanzaDirect(SAMPLE)),
            decodeStanzaDirect(encodeStanzaDirect(SAMPLE)),
        )
    })

    it('encodes an empty node', () => {
        const bytes = encodeBinaryNode({ tag: 'iq', attrs: {} })
        assert.ok(bytes.length > 0)
        const decoded = decodeBinaryNode(bytes)
        assert.equal(decoded.tag, 'iq')
        assert.deepEqual(decoded.attrs, {})
    })

    it('encodes unicode attributes', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: { notify: 'Ünïcödé 名前 🎉' },
        }
        const decoded = decodeBinaryNode(encodeBinaryNode(node))
        assert.equal(decoded.attrs.notify, 'Ünïcödé 名前 🎉')
    })

    it('encodes binary content', () => {
        const payload = new Uint8Array(256)
        for (let i = 0; i < payload.length; i += 1) payload[i] = i & 0xff
        const node: BinaryNode = {
            tag: 'enc',
            attrs: { v: '2' },
            content: payload,
        }
        const decoded = decodeBinaryNode(encodeBinaryNode(node))
        assert.ok(decoded.content instanceof Uint8Array)
        assert.deepEqual(decoded.content, payload)
    })

    it('keeps a text-like blob as raw bytes', () => {
        // The WAP format has no separate "text blob": a string and a byte
        // string share the same length-prefixed encoding. A blob that happens
        // to be valid UTF-8 must still decode to bytes, otherwise a Signal
        // pre-key id like `cc a9 0a` turns into the two character string
        // "̉\n" and the key bundle can no longer be parsed.
        const payload = new Uint8Array([0xcc, 0xa9, 0x0a])
        const node: BinaryNode = {
            tag: 'key',
            attrs: {},
            content: payload,
        }
        const decoded = decodeBinaryNode(encodeBinaryNode(node))
        assert.ok(decoded.content instanceof Uint8Array)
        assert.deepEqual(decoded.content, payload)
    })

    it('keeps a printable blob as raw bytes', () => {
        const payload = new TextEncoder().encode('hello world')
        const node: BinaryNode = {
            tag: 'value',
            attrs: {},
            content: payload,
        }
        const decoded = decodeBinaryNode(encodeBinaryNode(node))
        assert.ok(decoded.content instanceof Uint8Array)
        assert.deepEqual(decoded.content, payload)
    })

    it('preserves the order of the children', () => {
        const node: BinaryNode = {
            tag: 'iq',
            attrs: {},
            content: [
                { tag: 'a', attrs: { n: '1' } },
                { tag: 'b', attrs: { n: '2' } },
                { tag: 'c', attrs: { n: '3' } },
            ],
        }
        const decoded = decodeBinaryNode(encodeBinaryNode(node))
        assert.ok(Array.isArray(decoded.content))
        assert.deepEqual(
            decoded.content.map((child) => child.tag),
            ['a', 'b', 'c'],
        )
    })
})
