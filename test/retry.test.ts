/**
 * Retry receipt tests.
 *
 * A peer that cannot decrypt a message answers with a `<receipt type="retry">`
 * stanza. The tests cover the parsing of the stanza, the cache of the sent
 * messages and the stanza that answers the request.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    parseRetryReceipt,
    RETRY_REGISTRATION_ID_LENGTH,
} from '../src/protocol/retry.js'
import {
    OutboundMessageCache,
    OUTBOUND_MESSAGE_MAX_ENTRIES,
    OUTBOUND_MESSAGE_TTL_MS,
} from '../src/message/outbound-cache.js'
import {
    buildGroupRetryMessageNode,
    buildRetryMessageNode,
} from '../src/transport/node/builders/message.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

/**
 * Builds a retry receipt of the shape the server sends.
 *
 * @param attrs The attributes of the stanza.
 * @param children The children of the stanza.
 */
function buildRetryReceipt(
    attrs: Record<string, string>,
    children: BinaryNode[],
): BinaryNode {
    return {
        tag: 'receipt',
        attrs: {
            from: '120363431300536030@g.us',
            id: 'ACF0C53C746FE84F3BA4C8295C2D6CCF',
            ...attrs,
        },
        content: children,
    }
}

describe('retry receipt parsing', () => {
    it('parses a group retry receipt', () => {
        const node = buildRetryReceipt(
            {
                type: 'retry',
                participant: '111167158665409:3@lid',
                offline: '0',
                t: '1792907976',
            },
            [
                {
                    tag: 'registration',
                    attrs: {},
                    content: new Uint8Array([0, 0, 0, 0x33]),
                },
                {
                    tag: 'retry',
                    attrs: {
                        count: '1',
                        id: 'ACF0C53C746FE84F3BA4C8295C2D6CCF',
                        t: '1792907976',
                        v: '1',
                    },
                },
            ],
        )

        const request = parseRetryReceipt(node)
        assert.ok(request)
        assert.equal(request.type, 'retry')
        assert.equal(request.stanzaId, 'ACF0C53C746FE84F3BA4C8295C2D6CCF')
        assert.equal(request.from, '120363431300536030@g.us')
        assert.equal(request.participant, '111167158665409:3@lid')
        assert.equal(request.originalMsgId, 'ACF0C53C746FE84F3BA4C8295C2D6CCF')
        assert.equal(request.retryCount, 1)
        assert.equal(request.regId, 0x33)
    })

    it('reads the registration id as a big-endian number', () => {
        const node = buildRetryReceipt(
            { type: 'retry' },
            [
                {
                    tag: 'registration',
                    attrs: {},
                    content: new Uint8Array([0, 0, 0, 0xb6]),
                },
                { tag: 'retry', attrs: { count: '2', id: 'MSG1' } },
            ],
        )
        assert.equal(parseRetryReceipt(node)?.regId, 0xb6)
    })

    it('ignores a registration of the wrong length', () => {
        const node = buildRetryReceipt(
            { type: 'retry' },
            [
                {
                    tag: 'registration',
                    attrs: {},
                    content: new Uint8Array([1, 2]),
                },
                { tag: 'retry', attrs: { count: '1', id: 'MSG1' } },
            ],
        )
        const request = parseRetryReceipt(node)
        assert.ok(request)
        assert.equal(request.regId, undefined)
    })

    it('ignores the other receipt types', () => {
        for (const type of ['delivery', 'read', 'read-self', 'sender']) {
            const node = buildRetryReceipt({ type }, [
                { tag: 'retry', attrs: { count: '1', id: 'MSG1' } },
            ])
            assert.equal(parseRetryReceipt(node), null)
        }
    })

    it('ignores a receipt without a retry child', () => {
        const node = buildRetryReceipt({ type: 'retry' }, [])
        assert.equal(parseRetryReceipt(node), null)
    })

    it('ignores a retry child without an id', () => {
        const node = buildRetryReceipt({ type: 'retry' }, [
            { tag: 'retry', attrs: { count: '1' } },
        ])
        assert.equal(parseRetryReceipt(node), null)
    })

    it('reads the rekey retry type', () => {
        const node = buildRetryReceipt({ type: 'enc_rekey_retry' }, [
            { tag: 'retry', attrs: { count: '1', id: 'MSG1' } },
        ])
        assert.equal(parseRetryReceipt(node)?.type, 'enc_rekey_retry')
    })

    it('reports a missing count as zero', () => {
        const node = buildRetryReceipt({ type: 'retry' }, [
            { tag: 'retry', attrs: { id: 'MSG1' } },
        ])
        assert.equal(parseRetryReceipt(node)?.retryCount, 0)
    })

    it('knows the length of a registration id', () => {
        assert.equal(RETRY_REGISTRATION_ID_LENGTH, 4)
    })
})

describe('outbound message cache', () => {
    it('remembers a message', () => {
        const cache = new OutboundMessageCache()
        cache.set('MSG1', {
            to: '123@s.whatsapp.net',
            plaintext: new Uint8Array([1, 2, 3]),
            type: 'text',
            isGroup: false,
            sentAtMs: Date.now(),
        })
        const entry = cache.get('MSG1')
        assert.ok(entry)
        assert.equal(entry.to, '123@s.whatsapp.net')
        assert.equal(entry.type, 'text')
        assert.equal(entry.isGroup, false)
    })

    it('forgets a message that is too old', () => {
        const cache = new OutboundMessageCache({ ttlMs: 10 })
        cache.set('MSG1', {
            to: '123@s.whatsapp.net',
            plaintext: new Uint8Array([1]),
            type: 'text',
            isGroup: false,
            sentAtMs: Date.now() - 1000,
        })
        assert.equal(cache.get('MSG1'), undefined)
    })

    it('drops the oldest messages when it is full', () => {
        const cache = new OutboundMessageCache({ maxEntries: 2 })
        for (const id of ['A', 'B', 'C']) {
            cache.set(id, {
                to: '123@s.whatsapp.net',
                plaintext: new Uint8Array([1]),
                type: 'text',
                isGroup: false,
                sentAtMs: Date.now(),
            })
        }
        assert.equal(cache.size, 2)
        assert.equal(cache.get('A'), undefined)
        assert.ok(cache.get('B'))
        assert.ok(cache.get('C'))
    })

    it('forgets a message on demand', () => {
        const cache = new OutboundMessageCache()
        cache.set('MSG1', {
            to: '123@s.whatsapp.net',
            plaintext: new Uint8Array([1]),
            type: 'text',
            isGroup: false,
            sentAtMs: Date.now(),
        })
        cache.delete('MSG1')
        assert.equal(cache.get('MSG1'), undefined)
        assert.equal(cache.size, 0)
    })

    it('has sane defaults', () => {
        assert.equal(OUTBOUND_MESSAGE_TTL_MS, 5 * 60 * 1000)
        assert.equal(OUTBOUND_MESSAGE_MAX_ENTRIES, 256)
    })
})

/**
 * Returns the `<enc>` child of a stanza.
 *
 * @param node The stanza.
 */
function encOf(node: BinaryNode): BinaryNode {
    const content = node.content
    assert.ok(Array.isArray(content), 'the stanza carries no child nodes')
    const enc = content.find((child) => child.tag === 'enc')
    assert.ok(enc, 'the stanza carries no <enc> child')
    return enc
}

describe('retry message node', () => {
    it('builds a direct retry stanza', () => {
        const node = buildRetryMessageNode(
            { to: '123:2@s.whatsapp.net', type: 'text', id: 'MSG1' },
            'pkmsg',
            new Uint8Array([9, 9, 9]),
            1,
        )
        assert.equal(node.tag, 'message')
        assert.equal(node.attrs.to, '123:2@s.whatsapp.net')
        assert.equal(node.attrs.type, 'text')
        assert.equal(node.attrs.id, 'MSG1')
        assert.equal(node.attrs.participant, undefined)

        const enc = encOf(node)
        assert.equal(enc.tag, 'enc')
        assert.equal(enc.attrs.type, 'pkmsg')
        assert.equal(enc.attrs.count, '1')
        assert.equal(enc.attrs.v, '2')
    })

    it('builds a group retry stanza that names the requester', () => {
        const node = buildGroupRetryMessageNode(
            { to: '120363431300536030@g.us', type: 'text', id: 'MSG1' },
            'msg',
            new Uint8Array([7]),
            2,
            '111167158665409:3@lid',
        )
        assert.equal(node.attrs.to, '120363431300536030@g.us')
        assert.equal(node.attrs.participant, '111167158665409:3@lid')
        assert.equal(encOf(node).attrs.count, '2')
    })

    it('carries the media type of the original message', () => {
        const node = buildRetryMessageNode(
            {
                to: '123@s.whatsapp.net',
                type: 'image',
                id: 'MSG1',
                mediatype: 'image/jpeg',
            },
            'msg',
            new Uint8Array([1]),
            1,
        )
        assert.equal(encOf(node).attrs.mediatype, 'image/jpeg')
    })

    it('leaves the count out when there is none', () => {
        const node = buildRetryMessageNode(
            { to: '123@s.whatsapp.net', type: 'text', id: 'MSG1' },
            'msg',
            new Uint8Array([1]),
            0,
        )
        assert.equal(encOf(node).attrs.count, undefined)
    })
})
