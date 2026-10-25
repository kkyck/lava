/**
 * QR code tests.
 *
 * The QR encoder is used for device pairing, so the matrix has to be exactly
 * what the phone expects. The tests check the structural properties of the
 * matrix and compare against the published QR specification.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { encodeQr, qrToSvg, qrToTerminal } from '../src/qr/qrcode.js'
import {
    base64Decode,
    base64Encode,
    buildWhatsAppQrPayload,
    parseWhatsAppQrPayload,
} from '../src/qr/whatsapp.js'
import { base64UrlDecode, base64UrlEncode } from '../src/util/base64.js'
import { WA_COMPANION_PLATFORM_ID } from '../src/transport/node/builders/pairing.js'

describe('qr encoder', () => {
    it('produces a square matrix', () => {
        const matrix = encodeQr('hello')
        assert.ok(matrix.size > 0)
        assert.equal(matrix.modules.length, matrix.size)
        for (const row of matrix.modules) {
            assert.equal(row.length, matrix.size)
        }
    })

    it('places the three finder patterns in the corners', () => {
        const matrix = encodeQr('hello')
        const { size, modules } = matrix

        // The finder pattern is a 7x7 block with a dark border.
        const isFinder = (row: number, col: number): boolean => {
            const ring = Math.max(Math.abs(row - 3), Math.abs(col - 3))
            return ring === 3 || ring <= 1
        }
        const corners: [number, number][] = [
            [0, 0],
            [0, size - 7],
            [size - 7, 0],
        ]
        for (const [row, col] of corners) {
            for (let r = 0; r < 7; r += 1) {
                for (let c = 0; c < 7; c += 1) {
                    const actual = modules[row + r]?.[col + c] === true
                    assert.equal(
                        actual,
                        isFinder(r, c),
                        `finder pattern mismatch at ${row + r},${col + c}`,
                    )
                }
            }
        }
    })

    it('encodes different payloads into different matrices', () => {
        const a = encodeQr('payload one')
        const b = encodeQr('payload two')
        assert.notDeepEqual(a.modules, b.modules)
    })

    it('is deterministic', () => {
        assert.deepEqual(encodeQr('same').modules, encodeQr('same').modules)
    })

    it('renders an SVG', () => {
        const svg = qrToSvg(encodeQr('svg test'))
        assert.ok(svg.startsWith('<svg'))
        assert.ok(svg.includes('</svg>'))
    })

    it('renders to the terminal', () => {
        const text = qrToTerminal(encodeQr('terminal test'))
        assert.ok(text.length > 0)
        // The renderer uses half-block characters to double the resolution.
        assert.ok(/[▀▄█]/.test(text))
    })

    it('handles a long payload', () => {
        const payload = 'x'.repeat(2000)
        const matrix = encodeQr(payload)
        assert.ok(matrix.size > 21)
    })
})

describe('whatsapp qr payload', () => {
    it('builds a comma-separated payload', () => {
        const payload = buildWhatsAppQrPayload({
            ref: 'REF123',
            noisePublicKey: new Uint8Array(32).fill(1),
            identityPublicKey: new Uint8Array(32).fill(2),
            advSecret: new Uint8Array(32).fill(3),
            devicePlatform: '1',
        })
        const parts = payload.split(',')
        assert.equal(parts.length, 5)
        assert.equal(parts[0], 'REF123')
        assert.equal(parts[4], '1')
        assert.equal(base64Decode(parts[1]!)?.length, 32)
        assert.equal(base64Decode(parts[2]!)?.length, 32)
        assert.equal(base64Decode(parts[3]!)?.length, 32)
    })

    it('carries the client type in the last field', () => {
        // The phone shows the linked device under the name of the program
        // that links, so the payload ends with the client type — `1` for a
        // browser — and not with the name of the device.
        const payload = buildWhatsAppQrPayload({
            ref: 'REF123',
            noisePublicKey: new Uint8Array(32).fill(1),
            identityPublicKey: new Uint8Array(32).fill(2),
            advSecret: new Uint8Array(32).fill(3),
            devicePlatform: WA_COMPANION_PLATFORM_ID.CHROME,
        })
        assert.equal(payload.split(',')[4], '1')
    })

    it('round-trips through the parser', () => {
        const params = {
            ref: 'REF456',
            noisePublicKey: new Uint8Array(32).fill(4),
            identityPublicKey: new Uint8Array(32).fill(5),
            advSecret: new Uint8Array(32).fill(6),
            devicePlatform: '1',
        }
        const parsed = parseWhatsAppQrPayload(buildWhatsAppQrPayload(params))
        assert.ok(parsed)
        assert.equal(parsed.ref, params.ref)
        assert.equal(parsed.devicePlatform, params.devicePlatform)
        assert.deepEqual(parsed.noisePublicKey, params.noisePublicKey)
        assert.deepEqual(parsed.identityPublicKey, params.identityPublicKey)
        assert.deepEqual(parsed.advSecret, params.advSecret)
    })

    it('rejects a malformed payload', () => {
        assert.equal(parseWhatsAppQrPayload('too,few'), null)
        assert.equal(parseWhatsAppQrPayload('a,b,c,d,e'), null)
    })

    it('round-trips standard base64', () => {
        // 9 bytes is a multiple of three, so no padding is added.
        const exact = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
        assert.ok(!base64Encode(exact).endsWith('='))
        assert.deepEqual(base64Decode(base64Encode(exact)), exact)

        // 10 bytes needs two padding characters.
        const padded = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255, 7])
        assert.ok(base64Encode(padded).endsWith('=='))
        assert.deepEqual(base64Decode(base64Encode(padded)), padded)
    })

    it('round-trips base64url', () => {
        const data = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
        const encoded = base64UrlEncode(data)
        assert.ok(!encoded.includes('='))
        assert.ok(!encoded.includes('+'))
        assert.ok(!encoded.includes('/'))
        assert.deepEqual(base64UrlDecode(encoded), data)
    })
})
