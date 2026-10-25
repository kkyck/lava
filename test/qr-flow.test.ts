/**
 * QR-flow tests.
 *
 * The server hands out a handful of pairing references with every
 * `<pair-device>` stanza. Each of them is valid for a limited time, so the
 * client walks through them and shows the next QR code as the current one
 * expires. The tests below pin down that rotation down.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { QrFlow } from '../src/qr/flow.js'

/** Builds a flow that records every QR code it emits. */
function makeFlow(
    options: { initialTtlMs?: number; rotationTtlMs?: number } = {},
): { flow: QrFlow; emitted: { qr: string; ttlMs: number }[] } {
    const emitted: { qr: string; ttlMs: number }[] = []
    const flow = new QrFlow({
        buildQr: (ref) => `qr:${ref}`,
        emitQr: (qr, ttlMs) => {
            emitted.push({ qr, ttlMs })
        },
        initialTtlMs: options.initialTtlMs ?? 60_000,
        rotationTtlMs: options.rotationTtlMs ?? 20_000,
    })
    return { flow, emitted }
}

/** Waits for a condition to become true. */
async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('timed out waiting for the condition')
        await new Promise((resolve) => setTimeout(resolve, 2))
    }
}

describe('QR flow', () => {
    it('emits the first reference', () => {
        const { flow, emitted } = makeFlow()
        flow.setRefs(['a', 'b'])
        assert.equal(emitted.length, 1)
        assert.equal(emitted[0]?.qr, 'qr:a')
    })

    it('gives the first reference of a fresh set the long lifetime', () => {
        const { flow, emitted } = makeFlow()
        flow.setRefs(['a', 'b', 'c', 'd', 'e', 'f'])
        assert.equal(emitted[0]?.ttlMs, 60_000)
    })

    it('gives the following references the short lifetime', () => {
        const { flow, emitted } = makeFlow({ initialTtlMs: 100, rotationTtlMs: 20 })
        flow.setRefs(['a', 'b'])
        assert.equal(emitted[0]?.ttlMs, 20)
    })

    it('rotates to the next reference when the current one expires', async () => {
        const { flow, emitted } = makeFlow({ initialTtlMs: 60_000, rotationTtlMs: 20 })
        flow.setRefs(['a', 'b', 'c'])

        await waitFor(() => emitted.length >= 2)
        assert.equal(emitted[1]?.qr, 'qr:b')

        await waitFor(() => emitted.length >= 3)
        assert.equal(emitted[2]?.qr, 'qr:c')

        flow.clear()
    })

    it('stops after the last reference', async () => {
        const { flow, emitted } = makeFlow({ initialTtlMs: 60_000, rotationTtlMs: 20 })
        flow.setRefs(['a', 'b'])

        await waitFor(() => emitted.length >= 2)
        await new Promise((resolve) => setTimeout(resolve, 60))
        assert.equal(emitted.length, 2)

        flow.clear()
    })

    it('replaces the references with a fresh set', () => {
        const { flow, emitted } = makeFlow()
        flow.setRefs(['a', 'b'])
        flow.setRefs(['x', 'y'])
        assert.equal(emitted.length, 2)
        assert.equal(emitted[1]?.qr, 'qr:x')
        assert.equal(flow.remaining, 1)
    })

    it('shows the current reference again on a refresh', () => {
        const { flow, emitted } = makeFlow()
        flow.setRefs(['a', 'b'])
        assert.equal(flow.refreshCurrentQr(), true)
        assert.equal(emitted.length, 2)
        assert.equal(emitted[1]?.qr, 'qr:a')
    })

    it('cannot refresh before a reference was shown', () => {
        const { flow, emitted } = makeFlow()
        assert.equal(flow.refreshCurrentQr(), false)
        assert.equal(emitted.length, 0)
    })

    it('knows whether a QR code is available', () => {
        const { flow } = makeFlow()
        assert.equal(flow.hasQr, false)
        flow.setRefs(['a'])
        assert.equal(flow.hasQr, true)
        flow.clear()
        assert.equal(flow.hasQr, false)
    })

    it('drops the rotation when it is cleared', async () => {
        const { flow, emitted } = makeFlow({ initialTtlMs: 60_000, rotationTtlMs: 20 })
        flow.setRefs(['a', 'b'])
        flow.clear()

        await new Promise((resolve) => setTimeout(resolve, 60))
        assert.equal(emitted.length, 1)
    })
})
