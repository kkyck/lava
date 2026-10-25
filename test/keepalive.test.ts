/**
 * Keepalive tests.
 *
 * WhatsApp closes a socket that stays silent, so the client pings the server
 * every few seconds. The tests below pin down the three things that matter:
 * the ping goes out, a failing ping is reported, and a stopped keepalive
 * stays quiet.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { KeepAlive } from '../src/transport/keepalive.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

/** A ping recorder that answers every ping successfully. */
class RecordingQuery {
    /** The nodes that were queried. */
    readonly queries: BinaryNode[] = []
    /** The timeouts the queries were sent with. */
    readonly timeouts: (number | undefined)[] = []
    /** What the next ping answers with. */
    answer: (node: BinaryNode) => Promise<BinaryNode> = async () => ({
        tag: 'iq',
        attrs: { type: 'result' },
    })

    /** The query function the keepalive uses. */
    query = async (node: BinaryNode, timeoutMs?: number): Promise<BinaryNode> => {
        this.queries.push(node)
        this.timeouts.push(timeoutMs)
        return this.answer(node)
    }
}

/** Waits for a condition to become true. */
async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('timed out waiting for the condition')
        await new Promise((resolve) => setTimeout(resolve, 2))
    }
}

describe('keepalive', () => {
    it('pings the server with a `w:p` IQ', async () => {
        const recorder = new RecordingQuery()
        const keepAlive = new KeepAlive({ query: recorder.query, intervalMs: 20 })

        keepAlive.start()
        await waitFor(() => recorder.queries.length > 0)
        keepAlive.stop()

        const ping = recorder.queries[0]
        assert.equal(ping?.tag, 'iq')
        assert.equal(ping?.attrs.type, 'get')
        assert.equal(ping?.attrs.xmlns, 'w:p')
        assert.equal(ping?.attrs.to, 's.whatsapp.net')
    })

    it('sends the ping with the dead-socket timeout', async () => {
        const recorder = new RecordingQuery()
        const keepAlive = new KeepAlive({
            query: recorder.query,
            intervalMs: 20,
            timeoutMs: 1234,
        })

        keepAlive.start()
        await waitFor(() => recorder.timeouts.length > 0)
        keepAlive.stop()

        assert.equal(recorder.timeouts[0], 1234)
    })

    it('keeps pinging', async () => {
        const recorder = new RecordingQuery()
        const keepAlive = new KeepAlive({ query: recorder.query, intervalMs: 10 })

        keepAlive.start()
        await waitFor(() => recorder.queries.length >= 3)
        keepAlive.stop()

        assert.ok(recorder.queries.length >= 3)
    })

    it('reports a failing ping', async () => {
        const recorder = new RecordingQuery()
        recorder.answer = async () => {
            throw new Error('iq request timed out')
        }
        const failures: Error[] = []
        const keepAlive = new KeepAlive({
            query: recorder.query,
            intervalMs: 20,
            onFailure: (error) => failures.push(error),
        })

        keepAlive.start()
        await waitFor(() => failures.length > 0)
        keepAlive.stop()

        assert.equal(failures.length, 1)
        assert.match(failures[0]?.message ?? '', /timed out/)
    })

    it('stops pinging once it is stopped', async () => {
        const recorder = new RecordingQuery()
        const keepAlive = new KeepAlive({ query: recorder.query, intervalMs: 10 })

        keepAlive.start()
        await waitFor(() => recorder.queries.length > 0)
        keepAlive.stop()

        const seen = recorder.queries.length
        await new Promise((resolve) => setTimeout(resolve, 60))
        assert.equal(recorder.queries.length, seen)
    })

    it('does not report a failure of a stopped keepalive', async () => {
        const recorder = new RecordingQuery()
        // The ping stays in flight until the test releases it, so the
        // keepalive can be stopped while the ping is still running.
        let release: (() => void) | undefined
        const gate = new Promise<void>((resolve) => {
            release = resolve
        })
        recorder.answer = async () => {
            await gate
            throw new Error('iq request timed out')
        }
        const failures: Error[] = []
        const keepAlive = new KeepAlive({
            query: recorder.query,
            intervalMs: 20,
            onFailure: (error) => failures.push(error),
        })

        keepAlive.start()
        await waitFor(() => recorder.queries.length > 0)
        keepAlive.stop()
        release?.()
        await new Promise((resolve) => setTimeout(resolve, 60))

        assert.equal(failures.length, 0)
    })

    it('measures the clock skew the server reports', async () => {
        const recorder = new RecordingQuery()
        // The server answers with its own clock, in seconds.
        const serverSeconds = (Date.now() + 4000) / 1000
        recorder.answer = async () => ({
            tag: 'iq',
            attrs: { type: 'result', t: String(serverSeconds) },
        })
        const skews: number[] = []
        const keepAlive = new KeepAlive({
            query: recorder.query,
            intervalMs: 20,
            onClockSkewMs: (skewMs) => skews.push(skewMs),
        })

        keepAlive.start()
        await waitFor(() => skews.length > 0)
        keepAlive.stop()

        // The server runs about four seconds ahead of this machine.
        assert.ok((skews[0] ?? 0) > 3000, `expected a skew of ~4000ms, got ${skews[0]}`)
    })

    it('ignores a server that reports no clock', async () => {
        const recorder = new RecordingQuery()
        recorder.answer = async () => ({ tag: 'iq', attrs: { type: 'result' } })
        const skews: number[] = []
        const keepAlive = new KeepAlive({
            query: recorder.query,
            intervalMs: 20,
            onClockSkewMs: (skewMs) => skews.push(skewMs),
        })

        keepAlive.start()
        await waitFor(() => recorder.queries.length > 0)
        await new Promise((resolve) => setTimeout(resolve, 40))
        keepAlive.stop()

        assert.equal(skews.length, 0)
    })
})
