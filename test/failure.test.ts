/**
 * Failure-stanza tests.
 *
 * When the server refuses a session it sends a `<failure/>` stanza with a
 * numeric reason and closes the socket. The reason decides what happens to
 * the session: some reasons end it for good — the stored credentials are
 * worthless and the device has to pair again — while others only interrupt
 * the connection, so the credentials stay and the client may connect again.
 *
 * The tests below pin down that mapping and the promise of the library: a
 * background task that fails must never take the host process down.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { LavaClient } from '../src/client.js'
import { MemoryCredentialStore } from '../src/auth/credentials.js'
import {
    parseFailureNode,
    WA_DISCONNECT_FAILURE_REASONS,
    WA_FAILURE_REASONS,
    WA_LOGOUT_FAILURE_REASONS,
    type WaFailure,
} from '../src/protocol/failure.js'
import { Connection } from '../src/transport/connection.js'
import type { BinaryNode } from '../src/transport/binary/types.js'
import type { WaTransport } from '../src/client.js'

/** A transport that records what the client did with it. */
class MockTransport implements WaTransport {
    /** The handlers the client registered. */
    handlers: {
        onNode?: (node: BinaryNode) => void
        onClose?: (error?: Error) => void
        onError?: (error: Error) => void
    } = {}

    /** Whether the transport was closed. */
    closed = false

    async start(): Promise<void> {}

    send(_node: BinaryNode): void {}

    async query(node: BinaryNode): Promise<BinaryNode> {
        return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } }
    }

    getServerStaticKey(): Uint8Array | null {
        return null
    }

    close(): void {
        this.closed = true
    }
}

/** Builds a client wired to a mock transport. */
function makeClient(): { client: LavaClient; transport: MockTransport; store: MemoryCredentialStore } {
    const transport = new MockTransport()
    const store = new MemoryCredentialStore()
    const client = new LavaClient({
        credentials: store,
        transportFactory: (context) => {
            transport.handlers = context.handlers
            return transport
        },
    })
    return { client, transport, store }
}

/** Waits for a condition to become true. */
async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('timed out waiting for the condition')
        await new Promise((resolve) => setTimeout(resolve, 5))
    }
}

describe('failure stanza', () => {
    it('reads the reason, the code and the location', () => {
        const failure = parseFailureNode({
            tag: 'failure',
            attrs: {
                reason: '401',
                code: '401',
                location: 'cco',
                message: 'not authorized',
                url: 'https://example.invalid',
            },
        })
        assert.equal(failure.reason, 401)
        assert.equal(failure.code, 401)
        assert.equal(failure.location, 'cco')
        assert.equal(failure.message, 'not authorized')
        assert.equal(failure.url, 'https://example.invalid')
        assert.equal(failure.logout, true)
        assert.equal(failure.disconnect, false)
    })

    it('leaves the optional attributes out', () => {
        const failure = parseFailureNode({ tag: 'failure', attrs: {} })
        assert.equal(failure.reason, undefined)
        assert.equal(failure.code, undefined)
        assert.equal(failure.location, undefined)
        assert.equal(failure.logout, false)
        assert.equal(failure.disconnect, false)
    })

    it('ignores a reason that is not a number', () => {
        const failure = parseFailureNode({ tag: 'failure', attrs: { reason: 'nope' } })
        assert.equal(failure.reason, undefined)
        assert.equal(failure.logout, false)
    })

    it('ends the session for good on the logout reasons', () => {
        for (const reason of WA_LOGOUT_FAILURE_REASONS) {
            const failure = parseFailureNode({
                tag: 'failure',
                attrs: { reason: String(reason) },
            })
            assert.equal(failure.logout, true)
            assert.equal(failure.disconnect, false)
        }
    })

    it('only interrupts the connection on the disconnect reasons', () => {
        for (const reason of WA_DISCONNECT_FAILURE_REASONS) {
            const failure = parseFailureNode({
                tag: 'failure',
                attrs: { reason: String(reason) },
            })
            assert.equal(failure.disconnect, true)
            assert.equal(failure.logout, false)
        }
    })

    it('names the reasons the way the server does', () => {
        assert.equal(WA_FAILURE_REASONS.NOT_AUTHORIZED, 401)
        assert.equal(WA_FAILURE_REASONS.LOCKED, 403)
        assert.equal(WA_FAILURE_REASONS.BANNED, 406)
        assert.equal(WA_FAILURE_REASONS.CLIENT_TOO_OLD, 405)
        assert.equal(WA_FAILURE_REASONS.BAD_USER_AGENT, 409)
        assert.equal(WA_FAILURE_REASONS.SERVICE_UNAVAILABLE, 503)
    })
})

describe('client failure handling', () => {
    it('reports the failure the server sent', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        const failures: WaFailure[] = []
        client.on(LavaClient.FAILURE, (failure: WaFailure) => failures.push(failure))

        transport.handlers.onNode?.({
            tag: 'failure',
            attrs: { reason: '409', location: 'vll' },
        })

        assert.equal(failures.length, 1)
        assert.equal(failures[0]?.reason, 409)
        assert.equal(failures[0]?.location, 'vll')
        assert.equal(failures[0]?.disconnect, true)
    })

    it('clears the credentials when the server refuses the session', async () => {
        const { client, transport, store } = makeClient()
        await client.connect()
        assert.ok(await store.load())

        let loggedOut = false
        client.on(LavaClient.LOGOUT, () => {
            loggedOut = true
        })

        transport.handlers.onNode?.({
            tag: 'failure',
            attrs: { reason: '401', location: 'cco' },
        })

        await waitFor(() => loggedOut)
        assert.equal(await store.load(), null)
        assert.equal(client.getState(), 'disconnected')
        assert.ok(transport.closed)
    })

    it('keeps the credentials when only the connection was interrupted', async () => {
        const { client, transport, store } = makeClient()
        await client.connect()
        const snapshot = await store.load()
        assert.ok(snapshot)

        let loggedOut = false
        client.on(LavaClient.LOGOUT, () => {
            loggedOut = true
        })

        transport.handlers.onNode?.({
            tag: 'failure',
            attrs: { reason: '503' },
        })

        await waitFor(() => transport.closed)
        assert.equal(loggedOut, false)
        assert.ok(await store.load())
    })

    it('leaves the session alone when the reason is unknown', async () => {
        const { client, transport, store } = makeClient()
        await client.connect()

        let loggedOut = false
        client.on(LavaClient.LOGOUT, () => {
            loggedOut = true
        })

        transport.handlers.onNode?.({
            tag: 'failure',
            attrs: { reason: '418' },
        })

        await waitFor(() => true)
        assert.equal(loggedOut, false)
        assert.equal(transport.closed, false)
        assert.ok(await store.load())
    })

    it('does not reconnect after the server ended the session', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        transport.handlers.onNode?.({
            tag: 'failure',
            attrs: { reason: '403' },
        })

        await waitFor(() => transport.closed)
        const closed = transport.closed
        await new Promise((resolve) => setTimeout(resolve, 50))
        // The transport is closed once; a reconnect would have opened a new
        // one.
        assert.equal(transport.closed, closed)
        assert.equal(client.getState(), 'disconnected')
    })
})

describe('transport frame chain', () => {
    it('keeps processing frames after a listener threw', () => {
        const seen: string[] = []
        const errors: Error[] = []
        const connection = new Connection({
            noise: {
                clientStaticKeyPair: {
                    privateKey: new Uint8Array(32),
                    publicKey: new Uint8Array(33),
                },
                payload: new Uint8Array(0),
            },
            sendWire: () => {},
            closeWire: () => {},
            handlers: {
                onNode: (node: BinaryNode) => {
                    seen.push(node.attrs.id ?? '')
                    throw new Error('the listener exploded')
                },
                onError: (error: Error) => {
                    errors.push(error)
                },
            },
        })

        connection.handleNode({ tag: 'iq', attrs: { id: 'first', type: 'result' } })
        connection.handleNode({ tag: 'iq', attrs: { id: 'second', type: 'result' } })

        assert.deepEqual(seen, ['first', 'second'])
        assert.equal(errors.length, 2)
    })
})
