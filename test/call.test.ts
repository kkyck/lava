/**
 * Call-protocol tests.
 *
 * A call travels over the wire in one of two shapes: the classic `<call>`
 * stanza with a payload child, and the modern message whose body carries a
 * `call` field. The tests below pin down the reading of both, and the way
 * the client answers an inbound call — the peer waits for the answer before
 * it considers the call delivered.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { LavaClient } from '../src/client.js'
import { MemoryCredentialStore } from '../src/auth/credentials.js'
import {
    WA_CALL_RECEIPT_PAYLOADS,
    WA_CALL_STATUS,
    parseCallKey,
    parseCallNode,
    type WaInboundCall,
} from '../src/protocol/call.js'
import { ProtoWriter } from '../src/proto/codec.js'
import { buildCallOfferNode } from '../src/transport/node/builders.js'
import { findNodeChild } from '../src/transport/node/helpers.js'
import { isNodeList } from '../src/transport/binary/types.js'
import type { BinaryNode } from '../src/transport/binary/types.js'
import type { WaCallEvent, WaTransport } from '../src/client.js'

/** A transport that records what the client did with it. */
class MockTransport implements WaTransport {
    /** Every stanza the client sent. */
    readonly sent: BinaryNode[] = []

    /** The handlers the client registered. */
    handlers: {
        onNode?: (node: BinaryNode) => void
        onClose?: (error?: Error) => void
        onError?: (error: Error) => void
    } = {}

    async start(): Promise<void> {}

    send(node: BinaryNode): void {
        this.sent.push(node)
    }

    async query(node: BinaryNode): Promise<BinaryNode> {
        return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } }
    }

    getServerStaticKey(): Uint8Array | null {
        return null
    }

    close(): void {}

    /** Pushes an inbound stanza to the client. */
    push(node: BinaryNode): void {
        this.handlers.onNode?.(node)
    }
}

/** Builds a client wired to a mock transport. */
function makeClient(): { client: LavaClient; transport: MockTransport } {
    const transport = new MockTransport()
    const client = new LavaClient({
        credentials: new MemoryCredentialStore(),
        transportFactory: (context) => {
            transport.handlers = context.handlers
            return transport
        },
    })
    return { client, transport }
}

describe('call: the classic stanza', () => {
    it('reads the payload, the id and the creator of an offer', () => {
        const call = parseCallNode({
            tag: 'call',
            attrs: { from: '6281234567890@s.whatsapp.net', t: '1700000000' },
            content: [
                {
                    tag: 'offer',
                    attrs: {
                        'call-id': 'CALLID1',
                        'call-creator': '6281234567890@s.whatsapp.net',
                    },
                },
            ],
        })
        assert.equal(call.type, 'offer')
        assert.equal(call.payloadTag, 'offer')
        assert.equal(call.callId, 'CALLID1')
        assert.equal(call.creator, '6281234567890@s.whatsapp.net')
        assert.equal(call.video, false)
        assert.equal(call.timestamp, 1700000000)
    })

    it('knows a video call from the video child', () => {
        const call = parseCallNode({
            tag: 'call',
            attrs: {},
            content: [
                {
                    tag: 'offer',
                    attrs: { 'call-id': 'CALLID1' },
                    content: [{ tag: 'video', attrs: {} }],
                },
            ],
        })
        assert.equal(call.video, true)
    })

    it('reads the group a group call takes place in', () => {
        const call = parseCallNode({
            tag: 'call',
            attrs: { 'group-jid': '120363317298847177@g.us' },
            content: [{ tag: 'offer', attrs: { 'call-id': 'CALLID1' } }],
        })
        assert.equal(call.groupJid, '120363317298847177@g.us')
    })

    it('reads the participants of a group call', () => {
        const call = parseCallNode({
            tag: 'call',
            attrs: {},
            content: [
                {
                    tag: 'offer',
                    attrs: { 'call-id': 'CALLID1' },
                    content: [
                        {
                            tag: 'group_info',
                            attrs: {},
                            content: [
                                { tag: 'participant', attrs: { jid: '6281@s.whatsapp.net' } },
                                {
                                    tag: 'participant',
                                    attrs: { jid: '6282@s.whatsapp.net', user_pn: '6282' },
                                },
                            ],
                        },
                    ],
                },
            ],
        })
        assert.equal(call.participants?.length, 2)
        assert.equal(call.participants?.[0]?.jid, '6281@s.whatsapp.net')
        assert.equal(call.participants?.[1]?.userPnJid, '6282')
    })

    it('reads the name the caller goes by', () => {
        const call = parseCallNode({
            tag: 'call',
            attrs: { platform: 'android', version: '2.26.42.71' },
            content: [
                {
                    tag: 'offer',
                    attrs: { 'call-id': 'CALLID1', notify: 'Bot Zapo', username: 'botzapo' },
                },
            ],
        })
        assert.equal(call.callerPushName, 'Bot Zapo')
        assert.equal(call.callerUsername, 'botzapo')
        assert.equal(call.peerPlatform, 'android')
        assert.equal(call.peerAppVersion, '2.26.42.71')
    })

    it('reports an unknown payload as unknown', () => {
        const call = parseCallNode({
            tag: 'call',
            attrs: {},
            content: [{ tag: 'something_new', attrs: {} }],
        })
        assert.equal(call.type, 'unknown')
        assert.equal(call.payloadTag, 'something_new')
    })

    it('reports a stanza without a payload as unknown', () => {
        const call = parseCallNode({ tag: 'call', attrs: {} })
        assert.equal(call.type, 'unknown')
        assert.equal(call.video, false)
    })

    it('reads the payload the builder produces', () => {
        const node = buildCallOfferNode(
            '6281234567890@s.whatsapp.net',
            'CALLID1',
            '6285741949519@s.whatsapp.net',
            { video: true, timestamp: 1700000000 },
        )
        const call = parseCallNode(node)
        assert.equal(call.type, 'offer')
        assert.equal(call.callId, 'CALLID1')
        assert.equal(call.video, true)
        assert.equal(call.timestamp, 1700000000)
    })
})

describe('call: the payload statuses', () => {
    it('announces the transitions of a call', () => {
        assert.equal(WA_CALL_STATUS.offer, 'offer')
        assert.equal(WA_CALL_STATUS.offer_notice, 'offer')
        assert.equal(WA_CALL_STATUS.accept, 'accept')
        assert.equal(WA_CALL_STATUS.preaccept, 'accept')
        assert.equal(WA_CALL_STATUS.reject, 'reject')
        assert.equal(WA_CALL_STATUS.terminate, 'terminate')
    })

    it('says nothing about the payloads that carry no transition', () => {
        assert.equal(WA_CALL_STATUS.transport, undefined)
        assert.equal(WA_CALL_STATUS.mute, undefined)
        assert.equal(WA_CALL_STATUS.video_state, undefined)
    })

    it('answers the payloads the peer waits for with a receipt', () => {
        assert.equal(WA_CALL_RECEIPT_PAYLOADS.has('offer'), true)
        assert.equal(WA_CALL_RECEIPT_PAYLOADS.has('accept'), true)
        assert.equal(WA_CALL_RECEIPT_PAYLOADS.has('reject'), true)
        assert.equal(WA_CALL_RECEIPT_PAYLOADS.has('enc_rekey'), true)
        assert.equal(WA_CALL_RECEIPT_PAYLOADS.has('terminate'), false)
        assert.equal(WA_CALL_RECEIPT_PAYLOADS.has('mute'), false)
    })
})

describe('call: the key of a modern call message', () => {
    it('reads a call id that is plain text', () => {
        const key = parseCallKey(new TextEncoder().encode('CALLID1'))
        assert.equal(key.id, 'CALLID1')
    })

    it('reads a serialised key', () => {
        const writer = new ProtoWriter()
        writer.writeTag(1, 2)
        writer.writeBytes(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
        writer.writeTag(2, 2)
        writer.writeString('6281234567890@s.whatsapp.net')
        writer.writeTag(3, 0)
        writer.writeVarint(1n)
        const key = parseCallKey(writer.finish())
        assert.equal(key.id, 'deadbeef')
        assert.equal(key.chatJid, '6281234567890@s.whatsapp.net')
        assert.equal(key.fromMe, true)
    })

    it('reads a key that says nothing', () => {
        const key = parseCallKey(new Uint8Array(0))
        assert.equal(key.id, undefined)
    })
})

describe('client: the inbound call', () => {
    it('announces an incoming offer', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const calls: WaCallEvent[] = []
        client.on(LavaClient.CALL, (event) => calls.push(event))

        transport.push({
            tag: 'call',
            attrs: {
                id: 'STANZA1',
                from: '6281234567890@s.whatsapp.net',
                t: '1700000000',
            },
            content: [
                {
                    tag: 'offer',
                    attrs: {
                        'call-id': 'CALLID1',
                        'call-creator': '6281234567890@s.whatsapp.net',
                    },
                    content: [{ tag: 'video', attrs: {} }],
                },
            ],
        })

        assert.equal(calls.length, 1)
        assert.equal(calls[0]?.id, 'CALLID1')
        assert.equal(calls[0]?.jid, '6281234567890@s.whatsapp.net')
        assert.equal(calls[0]?.video, true)
        assert.equal(calls[0]?.direction, 'incoming')
        assert.equal(calls[0]?.status, 'offer')
    })

    it('answers an offer with a receipt that carries the payload back', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        transport.push({
            tag: 'call',
            attrs: { id: 'STANZA1', from: '6281234567890@s.whatsapp.net' },
            content: [
                {
                    tag: 'offer',
                    attrs: {
                        'call-id': 'CALLID1',
                        'call-creator': '6281234567890@s.whatsapp.net',
                    },
                },
            ],
        })

        const receipt = transport.sent.find((node) => node.tag === 'receipt')
        assert.ok(receipt)
        assert.equal(receipt.attrs.id, 'STANZA1')
        assert.equal(receipt.attrs.to, '6281234567890@s.whatsapp.net')
        assert.ok(isNodeList(receipt))
        const payload = receipt.content[0]
        assert.equal(payload?.tag, 'offer')
        assert.equal(payload?.attrs['call-id'], 'CALLID1')
        assert.equal(payload?.attrs['call-creator'], '6281234567890@s.whatsapp.net')
    })

    it('answers a payload the peer does not wait for with a plain acknowledgement', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        transport.push({
            tag: 'call',
            attrs: { id: 'STANZA1', from: '6281234567890@s.whatsapp.net' },
            content: [{ tag: 'mute', attrs: { 'call-id': 'CALLID1' } }],
        })

        const ack = transport.sent.find((node) => node.tag === 'ack')
        assert.ok(ack)
        assert.equal(ack.attrs.class, 'call')
        assert.equal(ack.attrs.type, 'mute')
        assert.equal(transport.sent.find((node) => node.tag === 'receipt'), undefined)
    })

    it('says nothing about a payload that carries no transition', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const calls: WaCallEvent[] = []
        client.on(LavaClient.CALL, (event) => calls.push(event))

        transport.push({
            tag: 'call',
            attrs: { id: 'STANZA1', from: '6281234567890@s.whatsapp.net' },
            content: [{ tag: 'mute', attrs: { 'call-id': 'CALLID1' } }],
        })

        assert.equal(calls.length, 0)
    })

    it('announces the end of a call', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const calls: WaCallEvent[] = []
        client.on(LavaClient.CALL, (event) => calls.push(event))

        transport.push({
            tag: 'call',
            attrs: { id: 'STANZA1', from: '6281234567890@s.whatsapp.net' },
            content: [{ tag: 'terminate', attrs: { 'call-id': 'CALLID1' } }],
        })

        assert.equal(calls.length, 1)
        assert.equal(calls[0]?.status, 'terminate')
    })
})
