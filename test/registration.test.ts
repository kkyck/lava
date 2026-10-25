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
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'

import {
    LavaRegistration,
    buildRegistrationForm,
    canonicalPhoneNumber,
    computeRegistrationToken,
    describeRegistrationFailure,
    encryptRegistrationPayload,
    parseCodeAnswer,
    parseExistAnswer,
    parsePhoneNumber,
    parseRegisterAnswer,
    toBase64Url,
    toUrlHex,
    type LavaRegistrationIdentity,
} from '../src/auth/registration.js'
import {
    FileCredentialStore,
    type CredentialSnapshot,
} from '../src/auth/credentials.js'
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

    it('brings a number into the form the server files it under', () => {
        assert.equal(canonicalPhoneNumber('+62 812 3456 7890'), '+6281234567890')
        assert.throws(() => canonicalPhoneNumber('081234567890'), /has no country code/)
    })
})

describe('registration: the material of a registration', () => {
    it('gives every registration its own material', () => {
        const first = LavaRegistration.createSession('+6281234567890', IDENTITY)
        const second = LavaRegistration.createSession('+6281234567890', IDENTITY)
        assert.notEqual(first.accessSessionId, second.accessSessionId)
        assert.notEqual(first.advertisingId, second.advertisingId)
        assert.notDeepEqual(first.identityId, second.identityId)
    })

    it('carries the material of an earlier registration over', () => {
        const first = LavaRegistration.createSession('+6281234567890', IDENTITY)
        const material = LavaRegistration.materialOf(first)
        const second = LavaRegistration.createSession('+6281234567890', IDENTITY, { material })
        // The server ties the code to the device that asked for it, so a
        // registration that continues after a restart has to look the same.
        assert.deepEqual(second.identityId, first.identityId)
        assert.deepEqual(second.deviceId, first.deviceId)
        assert.equal(second.advertisingId, first.advertisingId)
        assert.equal(second.installId, first.installId)
        assert.equal(second.accessSessionId, first.accessSessionId)
    })

    it('keeps the material in the credential snapshot', async () => {
        const path = join(tmpdir(), `lava-registration-${process.pid}.json`)
        const store = new FileCredentialStore(path)
        const material = {
            phoneNumber: '+6281234567890',
            deviceId: 'AAAA',
            identityId: 'BBBB',
            advertisingId: 'cccc',
            installId: 'dddd',
            accessSessionId: 'EEEE',
        }
        await store.save({ version: 1, registration: material } as unknown as CredentialSnapshot)
        const loaded = await store.load()
        assert.deepEqual(loaded?.registration, material)
        await rm(path, { force: true })
    })
})

/**
 * The answer of the `/exist` endpoint.
 *
 * The endpoint refuses a request it cannot make sense of, and it refuses it
 * the same way for every number — so an answer like this says nothing about
 * the number that was asked about.
 */
const REFUSED_EXIST = {
    status: 'fail',
    reason: 'incorrect',
    login: '6285741949519',
    num_visible_dbs_methods: 3,
    fallback_methods: ['passkey', 'password', 'wa_old', 'email_otp', 'flash', 'sms', 'voice'],
    sms_length: 6,
    voice_length: 6,
}

describe('registration: the answer about a number', () => {
    it('reports a refusal as inconclusive instead of guessing', () => {
        const status = parseExistAnswer(REFUSED_EXIST)
        // The server did not rule on the number, so neither did Lava.
        assert.equal(status.conclusive, false)
        assert.equal(status.registered, false)
        assert.equal(status.canRegister, false)
        assert.equal(status.reason, 'incorrect')
        assert.equal(status.canonicalNumber, '6285741949519')
    })

    it('reports a number the server does not know as claimable', () => {
        const status = parseExistAnswer({
            status: 'fail',
            reason: 'missing',
            state: 'missing',
            num_visible_dbs_methods: 3,
        })
        assert.equal(status.conclusive, true)
        assert.equal(status.registered, false)
        assert.equal(status.canRegister, true)
    })

    it('reports an account the server knows', () => {
        const status = parseExistAnswer({
            status: 'ok',
            state: 'existing',
            login: '6285741949519',
        })
        assert.equal(status.conclusive, true)
        assert.equal(status.registered, true)
        assert.equal(status.canRegister, false)
    })

    it('reports a request the server choked on as an error', () => {
        assert.throws(
            () => parseExistAnswer({ status: 'fail', reason: 'missing_param', param: 'e_skey_sig' }),
            /parameter "e_skey_sig"/,
        )
        assert.throws(
            () => parseExistAnswer({ status: 'fail', failure_reason: 'bad_format', param: 'fdid' }),
            /bad_format/,
        )
    })
})

describe('registration: the answer about a code', () => {
    it('reads the method, the length and the waits of a sent code', () => {
        const request = parseCodeAnswer(
            {
                status: 'sent',
                method: 'sms',
                login: '18005550100',
                length: 6,
                sms_wait: 5,
                send_sms_wait: 65,
                voice_wait: 65,
                flash_wait: 65,
                retry_after: 5,
                notify_after: 86400,
                num_visible_dbs_methods: 3,
            },
            'sms',
        )
        assert.equal(request.ok, true)
        assert.equal(request.method, 'sms')
        assert.equal(request.length, 6)
        assert.equal(request.wait, 5)
        assert.equal(request.retryAfter, 5)
        assert.equal(request.canonicalNumber, '18005550100')
    })

    it('lets the server choose another method than the one asked for', () => {
        const request = parseCodeAnswer({ status: 'sent', method: 'voice' }, 'sms')
        assert.equal(request.method, 'voice')
    })

    it('falls back to the send wait when the method has none of its own', () => {
        const request = parseCodeAnswer({ status: 'sent', send_sms_wait: 65 }, 'sms')
        assert.equal(request.wait, 65)
    })

    it('reports a refused code with its reason', () => {
        const request = parseCodeAnswer(
            { status: 'fail', reason: 'temporarily_unavailable', retry_after: 300 },
            'voice',
        )
        assert.equal(request.ok, false)
        assert.equal(request.reason, 'temporarily_unavailable')
        assert.equal(request.retryAfter, 300)
    })

    it('reports a request the server choked on as an error', () => {
        assert.throws(
            () => parseCodeAnswer({ status: 'fail', reason: 'missing_param', param: 'token' }, 'sms'),
            /parameter "token"/,
        )
    })
})

describe('registration: the answer about a claimed number', () => {
    it('reads a claimed number', () => {
        const result = parseRegisterAnswer({ status: 'ok', login: '6285741949519' })
        assert.equal(result.ok, true)
        assert.equal(result.canonicalNumber, '6285741949519')
    })

    it('reports a refused code', () => {
        const result = parseRegisterAnswer({ status: 'fail', reason: 'mismatch' })
        assert.equal(result.ok, false)
        assert.equal(result.reason, 'mismatch')
    })

    it('describes why the server refused a code', () => {
        assert.match(describeRegistrationFailure('mismatch'), /not accepted/)
        assert.match(describeRegistrationFailure('temporarily_unavailable'), /busy/)
        assert.match(describeRegistrationFailure('too_recent'), /too recently/)
        assert.match(describeRegistrationFailure(undefined), /refused/)
        assert.equal(describeRegistrationFailure('something_new'), 'something_new')
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
