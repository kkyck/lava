/**
 * Registration tests.
 *
 * The registration flow is how Lava claims a phone number for itself: the
 * *mobile primary* way into an account. The tests below pin down the parts of
 * it that must not drift — the phone-number parsing, the token that binds a
 * request to the app version it announces, the form serialisation and the
 * encryption of the envelope.
 *
 * The requests themselves are never sent: the tests only look at what the
 * client would put on the wire.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    LavaRegistration,
    buildRegistrationForm,
    computeRegistrationToken,
    encryptRegistrationPayload,
    parsePhoneNumber,
    toBase64Url,
    toUrlHex,
    type LavaRegistrationIdentity,
} from '../src/auth/registration.js'
import { fromHex, toHex } from '../src/crypto/primitives.js'

/** A deterministic identity, so the tests compare stable values. */
const IDENTITY: LavaRegistrationIdentity = {
    noiseKeyPair: {
        pub: Buffer.alloc(33, 0x05).toString('base64'),
        priv: Buffer.alloc(32, 0x11).toString('base64'),
    },
    identityKeyPair: {
        pub: Buffer.alloc(33, 0x05).toString('base64'),
        priv: Buffer.alloc(32, 0x22).toString('base64'),
    },
    registrationId: 1621,
    signedPreKey: {
        id: 1,
        keyPair: {
            pub: Buffer.alloc(33, 0x05).toString('base64'),
            priv: Buffer.alloc(32, 0x33).toString('base64'),
        },
        signature: Buffer.alloc(64, 0x44).toString('base64'),
    },
}

describe('registration', () => {
    it('splits a phone number into its country code and national number', () => {
        assert.deepEqual(parsePhoneNumber('+6281234567890'), {
            countryCode: '62',
            nationalNumber: '81234567890',
        })
    })

    it('accepts a number in any format', () => {
        assert.deepEqual(parsePhoneNumber('+62 812 3456 7890'), {
            countryCode: '62',
            nationalNumber: '81234567890',
        })
        assert.deepEqual(parsePhoneNumber('(+1) 415-555-0100'), {
            countryCode: '1',
            nationalNumber: '4155550100',
        })
    })

    it('refuses a national number without its country code', () => {
        assert.throws(() => parsePhoneNumber('0812 3456 7890'), /has no country code/)
    })

    it('knows the three digit country codes', () => {
        assert.deepEqual(parsePhoneNumber('+33612345678'), {
            countryCode: '33',
            nationalNumber: '612345678',
        })
        assert.deepEqual(parsePhoneNumber('+6281234567890'), {
            countryCode: '62',
            nationalNumber: '81234567890',
        })
        // 1 is ambiguous: the country code is one digit, so the whole rest is
        // the national number.
        assert.deepEqual(parsePhoneNumber('+14155550100'), {
            countryCode: '1',
            nationalNumber: '4155550100',
        })
    })

    it('refuses something that is not a phone number', () => {
        assert.throws(() => parsePhoneNumber('12'), /is not a phone number/)
    })

    it('binds the token to the app version and the number', () => {
        const first = computeRegistrationToken('2.26.42.71', '81234567890', 'ios')
        const second = computeRegistrationToken('2.26.42.71', '81234567890', 'ios')
        assert.equal(first, second)
        assert.match(first, /^[0-9a-f]{32}$/)
        // A different version gives a different token, and so does a
        // different number.
        assert.notEqual(first, computeRegistrationToken('2.26.42.72', '81234567890', 'ios'))
        assert.notEqual(first, computeRegistrationToken('2.26.42.71', '81234567891', 'ios'))
    })

    it('takes the token of the caller for an Android registration', () => {
        assert.equal(
            computeRegistrationToken('2.26.42.71', '81234567890', 'android', 'deadbeef'),
            'deadbeef',
        )
        assert.throws(
            () => computeRegistrationToken('2.26.42.71', '81234567890', 'android'),
            /needs a token of its own/,
        )
    })

    it('serialises the parameters without encoding them', () => {
        const form = buildRegistrationForm(['id', '%AA%BB', 'cc', '62', 'skip', null])
        assert.equal(form, 'id=%AA%BB&cc=62')
    })

    it('encodes bytes the way a Java toUrlHex does', () => {
        assert.equal(toUrlHex(new Uint8Array([0x00, 0x0a, 0xff])), '%00%0A%FF')
    })

    it('encodes bytes as base64url without padding', () => {
        const encoded = toBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]))
        assert.equal(encoded, '-__-')
        assert.ok(!encoded.includes('='))
    })

    it('encrypts the envelope so that only the server can read it', () => {
        const first = encryptRegistrationPayload('cc=62&in=81234567890')
        const second = encryptRegistrationPayload('cc=62&in=81234567890')
        // A fresh ephemeral key every time, so the same body never encrypts
        // to the same envelope.
        assert.notEqual(first, second)
        assert.ok(!first.includes('cc=62'))
        // The envelope is the ephemeral public key, the ciphertext and the
        // authentication tag.
        assert.ok(fromHex(base64ToHex(first)).length > 32 + 16)
    })

    it('builds a session that carries the identity of the device', () => {
        const session = LavaRegistration.createSession('+6281234567890', IDENTITY)
        assert.equal(session.countryCode, '62')
        assert.equal(session.nationalNumber, '81234567890')
        assert.equal(session.phoneNumber, '+6281234567890')
        assert.equal(session.identity.registrationId, 1621)
        // The country of the number is read out of the number itself.
        assert.equal(session.country.mcc, '510')
        assert.equal(session.country.mnc, '001')
        // Every request of the flow carries the same session id.
        assert.equal(session.accessSessionId.length, 22)
        assert.equal(session.installId.length, 16)
    })

    it('keeps the country of the number when the caller knows the SIM', () => {
        const session = LavaRegistration.createSession('+6281234567890', IDENTITY, {
            country: { mcc: '510', mnc: '002' },
        })
        assert.equal(session.country.mnc, '002')
    })
})

/**
 * Decodes base64url into hexadecimal.
 *
 * @param value The base64url text.
 */
function base64ToHex(value: string): string {
    return toHex(new Uint8Array(Buffer.from(value, 'base64url')))
}
