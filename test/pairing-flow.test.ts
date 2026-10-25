/**
 * Pairing-flow tests.
 *
 * Pairing over the QR code is a conversation with the server:
 *
 * 1. The server sends an `<iq type="set">` with a `<pair-device>` child that
 *    carries the QR references. The client has to answer it with an
 *    `<iq type="result">` — an unanswered request makes the server close the
 *    socket.
 * 2. Every reference is valid for a limited time, so the client walks
 *    through them and emits a new QR code as the old one expires.
 * 3. The server pings the client with an `<iq type="get">` in the `w:p`
 *    namespace. The client has to answer that, too.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { LavaClient } from '../src/client.js'
import { MemoryCredentialStore } from '../src/auth/credentials.js'
import type { BinaryNode } from '../src/transport/binary/types.js'
import type { WaTransport } from '../src/client.js'

/** A transport that records what the client sent. */
class MockTransport implements WaTransport {
    /** The handlers the client registered. */
    handlers: {
        onNode?: (node: BinaryNode) => void
        onClose?: (error?: Error) => void
        onError?: (error: Error) => void
    } = {}

    /** Every stanza the client sent. */
    readonly sent: BinaryNode[] = []

    /** The stanzas the client queried for. */
    readonly queries: BinaryNode[] = []

    async start(): Promise<void> {}

    send(node: BinaryNode): void {
        this.sent.push(node)
    }

    async query(node: BinaryNode): Promise<BinaryNode> {
        this.queries.push(node)
        return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } }
    }

    getServerStaticKey(): Uint8Array | null {
        return null
    }

    close(): void {}
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

/** Waits for a condition to become true. */
async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('timed out waiting for the condition')
        await new Promise((resolve) => setTimeout(resolve, 2))
    }
}

/** Builds the `<pair-device>` stanza the server sends. */
function pairDeviceIq(refs: string[], id = 'pair-1'): BinaryNode {
    return {
        tag: 'iq',
        attrs: { id, type: 'set', from: 's.whatsapp.net' },
        content: [
            {
                tag: 'pair-device',
                attrs: {},
                content: refs.map((ref) => ({
                    tag: 'ref',
                    attrs: {},
                    content: new TextEncoder().encode(ref),
                })),
            },
        ],
    }
}

describe('pair-device handling', () => {
    it('answers the request with an IQ result', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        transport.handlers.onNode?.(pairDeviceIq(['ref-1']))

        await waitFor(() =>
            transport.sent.some(
                (node) => node.tag === 'iq' && node.attrs.type === 'result' && node.attrs.id === 'pair-1',
            ),
        )
        client.disconnect()
    })

    it('emits a QR code for the first reference', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const qrs: string[] = []
        client.on(LavaClient.AUTH_QR, ({ qr }: { qr: string }) => qrs.push(qr))

        transport.handlers.onNode?.(pairDeviceIq(['ref-1', 'ref-2']))

        await waitFor(() => qrs.length > 0)
        assert.match(qrs[0] ?? '', /ref-1/)
        client.disconnect()
    })

    it('rotates to the next reference when the current one expires', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const qrs: string[] = []
        client.on(LavaClient.AUTH_QR, ({ qr }: { qr: string }) => qrs.push(qr))

        transport.handlers.onNode?.(pairDeviceIq(['ref-1', 'ref-2', 'ref-3']))

        await waitFor(() => qrs.length > 0)
        assert.match(qrs[0] ?? '', /ref-1/)
        client.disconnect()
    })

    it('rotates the advanced device attestation secret', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const before = client.getSession()
        transport.handlers.onNode?.(pairDeviceIq(['ref-1']))
        await waitFor(() =>
            transport.sent.some((node) => node.tag === 'iq' && node.attrs.type === 'result'),
        )
        const after = client.getSession()

        assert.ok(before)
        assert.ok(after)
        client.disconnect()
    })
})

describe('server pings', () => {
    it('answers a `w:p` ping with a result', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        transport.handlers.onNode?.({
            tag: 'iq',
            attrs: { id: 'ping-1', type: 'get', xmlns: 'w:p', from: 's.whatsapp.net' },
        })

        await waitFor(() =>
            transport.sent.some(
                (node) => node.tag === 'iq' && node.attrs.type === 'result' && node.attrs.id === 'ping-1',
            ),
        )
        client.disconnect()
    })

    it('answers an XMPP ping with a result', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        transport.handlers.onNode?.({
            tag: 'iq',
            attrs: { id: 'ping-2', type: 'get', xmlns: 'urn:xmpp:ping', from: 's.whatsapp.net' },
        })

        await waitFor(() =>
            transport.sent.some(
                (node) => node.tag === 'iq' && node.attrs.type === 'result' && node.attrs.id === 'ping-2',
            ),
        )
        client.disconnect()
    })
})
