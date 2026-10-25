/**
 * Connection tests.
 *
 * The connection owns the request/response bookkeeping of the protocol. The
 * tests below pin down the behaviour that matters for the host process: a
 * request that cannot go out must not leave a promise behind that rejects
 * later on its own — an unhandled rejection would take the process down.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { Connection } from '../src/transport/connection.js'
import { IqDispatcher } from '../src/transport/node/query.js'
import { generateX25519KeyPair } from '../src/crypto/primitives.js'

/** Builds a connection that is not connected to anything. */
function closedConnection(): Connection {
    const keyPair = generateX25519KeyPair()
    return new Connection({
        noise: {
            clientStaticKeyPair: {
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
            },
            payload: new Uint8Array(0),
        },
        sendWire: () => undefined,
        closeWire: () => undefined,
    })
}

describe('iq dispatcher', () => {
    it('drops a request without answering it', async () => {
        const dispatcher = new IqDispatcher()
        const response = dispatcher.expect('id-1', 20)
        assert.equal(dispatcher.discard('id-1'), true)

        /**
         * The promise of a dropped request stays unsettled. A rejection
         * would be an unhandled rejection, because nobody waits for it.
         */
        const outcome = await Promise.race([
            response.then(
                () => 'settled',
                () => 'rejected',
            ),
            new Promise((resolve) => setTimeout(() => resolve('pending'), 80)),
        ])
        assert.equal(outcome, 'pending')
    })

    it('reports a request it does not know', () => {
        const dispatcher = new IqDispatcher()
        assert.equal(dispatcher.discard('id-2'), false)
    })
})

describe('connection', () => {
    it('rejects a request whose socket is closed', async () => {
        const connection = closedConnection()
        connection.close()
        await assert.rejects(
            () =>
                connection.query({
                    tag: 'iq',
                    attrs: { to: 's.whatsapp.net', type: 'get', xmlns: 'w:p' },
                }),
            /connection is closed/,
        )
    })

    it('leaves no request behind when the socket is closed', async () => {
        const connection = closedConnection()
        connection.close()

        const rejections: unknown[] = []
        const onRejection = (reason: unknown) => rejections.push(reason)
        process.on('unhandledRejection', onRejection)

        await assert.rejects(() =>
            connection.query({
                tag: 'iq',
                attrs: { to: 's.whatsapp.net', type: 'get', xmlns: 'w:p' },
            }),
        )

        /**
         * The request would have timed out on its own after twenty seconds
         * and rejected with nobody listening to it. The test waits long
         * enough for a short timeout to make sure the promise is gone.
         */
        await new Promise((resolve) => setTimeout(resolve, 120))
        process.off('unhandledRejection', onRejection)
        assert.deepEqual(rejections, [])
    })
})
