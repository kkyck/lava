/**
 * Pairing and device-list tests.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    CROCKFORD_ALPHABET,
    completeCompanionFinish,
    createCompanionHello,
    encodeBytesToCrockford,
    normalizeCustomPairingCode,
} from '../src/auth/pairing.js'
import {
    aesCtrDecrypt,
    aesCtrEncrypt,
    aesGcmDecrypt,
    hkdf,
    pbkdf2Sha256,
    utf8,
    x25519,
    x25519PublicFromPrivate,
} from '../src/crypto/primitives.js'
import { generateRegistrationInfo } from '../src/signal/keys.js'
import {
    DeviceListStore,
    buildDeviceListUsyncIq,
    parseDeviceListResponse,
} from '../src/signal/device-list.js'
import { findNodeChild } from '../src/transport/node/helpers.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

describe('pairing codes', () => {
    it('generates an eight-character code', async () => {
        const hello = await createCompanionHello()
        assert.equal(hello.pairingCode.length, 8)
        for (const char of hello.pairingCode) {
            assert.ok(CROCKFORD_ALPHABET.includes(char), `unexpected character ${char}`)
        }
    })

    it('generates a different code every time', async () => {
        const first = await createCompanionHello()
        const second = await createCompanionHello()
        assert.notEqual(first.pairingCode, second.pairingCode)
        assert.notDeepEqual(first.companionEphemeralPrivateKey, second.companionEphemeralPrivateKey)
    })

    it('accepts a custom code', async () => {
        const hello = await createCompanionHello({ customCode: 'ABCD-2345' })
        assert.equal(hello.pairingCode, 'ABCD2345')
    })

    it('normalises a custom code', () => {
        assert.equal(normalizeCustomPairingCode('abcd-efgh'), 'ABCDEFGH')
        assert.equal(normalizeCustomPairingCode('ABCDEFGH'), 'ABCDEFGH')
    })

    it('rejects a custom code of the wrong length', () => {
        assert.throws(() => normalizeCustomPairingCode('ABC'))
        assert.throws(() => normalizeCustomPairingCode('ABCDEFGHI'))
    })

    it('rejects a character outside the Crockford alphabet', () => {
        // The Crockford base32 alphabet excludes I, L, O and U.
        assert.throws(() => normalizeCustomPairingCode('ABCDEFGI'), /invalid character/)
    })

    it('encodes bytes with the Crockford alphabet', () => {
        const encoded = encodeBytesToCrockford(new Uint8Array([0, 0, 0, 0, 0]))
        assert.equal(encoded.length, 8)
        for (const char of encoded) assert.ok(CROCKFORD_ALPHABET.includes(char))
    })
})

describe('companion handshake', () => {
    it('derives a shared secret from both sides', async () => {
        const companion = await createCompanionHello()
        const registration = generateRegistrationInfo()

        // The primary side unwraps the companion's ephemeral public key with
        // the pairing code.
        const salt = companion.wrappedCompanionEphemeralPub.subarray(0, 32)
        const counter = companion.wrappedCompanionEphemeralPub.subarray(32, 48)
        const ciphertext = companion.wrappedCompanionEphemeralPub.subarray(48)
        const cipherKey = pbkdf2Sha256(utf8(companion.pairingCode), salt, 2 << 16, 32)
        const unwrappedCompanionPub = aesCtrDecrypt(cipherKey, counter, ciphertext)
        assert.deepEqual(unwrappedCompanionPub, companion.companionEphemeralPublicKey)

        // The primary wraps its own ephemeral key the same way.
        const primaryPrivate = new Uint8Array(32).fill(7)
        const primaryPublic = x25519PublicFromPrivate(primaryPrivate)
        const primarySalt = new Uint8Array(32).fill(3)
        const primaryCounter = new Uint8Array(16).fill(4)
        const wrappedPrimary = new Uint8Array(
            primarySalt.length + primaryCounter.length + primaryPublic.length,
        )
        wrappedPrimary.set(primarySalt, 0)
        wrappedPrimary.set(primaryCounter, primarySalt.length)
        wrappedPrimary.set(
            aesCtrEncrypt(
                pbkdf2Sha256(utf8(companion.pairingCode), primarySalt, 2 << 16, 32),
                primaryCounter,
                primaryPublic,
            ),
            primarySalt.length + primaryCounter.length,
        )

        const finish = await completeCompanionFinish({
            pairingCode: companion.pairingCode,
            companionEphemeralPrivateKey: companion.companionEphemeralPrivateKey,
            identityKeyPair: registration.identityKeyPair,
            wrappedPrimaryEphemeralPub: wrappedPrimary,
            primaryIdentityPub: new Uint8Array(32).fill(9),
        })

        assert.ok(finish.wrappedKeyBundle.length > 0)
        assert.equal(finish.advSecret.length, 32)

        // The shared ephemeral secret must match on both sides.
        const shared = x25519(companion.companionEphemeralPrivateKey, primaryPublic)
        const mirrored = x25519(primaryPrivate, companion.companionEphemeralPublicKey)
        assert.deepEqual(shared, mirrored)
    })

    it('puts the raw identity keys into the key bundle', async () => {
        const companion = await createCompanionHello()
        const registration = generateRegistrationInfo()
        const primaryIdentityPub = new Uint8Array(32).fill(9)

        // The identity key pair is kept in its serialized form — 33 bytes
        // with the version byte — but the bundle carries the raw form: the
        // phone compares the bundle against the raw key it owns.
        assert.equal(registration.identityKeyPair.pubKey.length, 33)

        const primaryPrivate = new Uint8Array(32).fill(7)
        const primaryPublic = x25519PublicFromPrivate(primaryPrivate)
        const primarySalt = new Uint8Array(32).fill(3)
        const primaryCounter = new Uint8Array(16).fill(4)
        const wrappedPrimary = new Uint8Array(32 + 16 + 32)
        wrappedPrimary.set(primarySalt, 0)
        wrappedPrimary.set(primaryCounter, 32)
        wrappedPrimary.set(
            aesCtrEncrypt(
                pbkdf2Sha256(utf8(companion.pairingCode), primarySalt, 2 << 16, 32),
                primaryCounter,
                primaryPublic,
            ),
            48,
        )

        const finish = await completeCompanionFinish({
            pairingCode: companion.pairingCode,
            companionEphemeralPrivateKey: companion.companionEphemeralPrivateKey,
            identityKeyPair: registration.identityKeyPair,
            wrappedPrimaryEphemeralPub: wrappedPrimary,
            primaryIdentityPub,
        })

        // The identity public key goes out in its raw form.
        assert.equal(finish.companionIdentityPublic.length, 32)
        assert.deepEqual(
            finish.companionIdentityPublic,
            registration.identityKeyPair.pubKey.subarray(1),
        )

        // The bundle is `salt ‖ iv ‖ ciphertext`; the plaintext holds the
        // raw identity keys and the shared secret.
        const bundleSalt = finish.wrappedKeyBundle.subarray(0, 32)
        const bundleIv = finish.wrappedKeyBundle.subarray(32, 44)
        const ciphertext = finish.wrappedKeyBundle.subarray(44)
        const sharedEphemeral = x25519(
            companion.companionEphemeralPrivateKey,
            primaryPublic,
        )
        const bundleKey = hkdf(
            sharedEphemeral,
            bundleSalt,
            utf8('link_code_pairing_key_bundle_encryption_key'),
            32,
        )
        const plaintext = aesGcmDecrypt(bundleKey, bundleIv, ciphertext)
        assert.deepEqual(plaintext.subarray(0, 32), finish.companionIdentityPublic)
        assert.deepEqual(plaintext.subarray(32, 64), primaryIdentityPub)
        assert.equal(plaintext.length, 96)
    })

    it('rejects a truncated wrapped payload', async () => {
        const registration = generateRegistrationInfo()
        await assert.rejects(
            completeCompanionFinish({
                pairingCode: 'ABCDEFGH',
                companionEphemeralPrivateKey: new Uint8Array(32),
                identityKeyPair: registration.identityKeyPair,
                wrappedPrimaryEphemeralPub: new Uint8Array(10),
                primaryIdentityPub: new Uint8Array(32),
            }),
            /invalid wrapped primary payload/,
        )
    })
})

describe('device list', () => {
    it('builds the usync IQ', () => {
        const iq = buildDeviceListUsyncIq(['123@s.whatsapp.net'], 'SID')
        assert.equal(iq.tag, 'iq')
        assert.equal(iq.attrs.xmlns, 'usync')
        const usync = findNodeChild(iq, 'usync')
        assert.ok(usync)
        assert.equal(usync.attrs.sid, 'SID')
        const query = findNodeChild(usync, 'query')
        assert.ok(query)
        const devices = findNodeChild(query, 'devices')
        assert.ok(devices)
        assert.equal(devices.attrs.version, '2')
    })

    it('parses a device list response', () => {
        const response: BinaryNode = {
            tag: 'iq',
            attrs: { id: '1', type: 'result' },
            content: [
                {
                    tag: 'usync',
                    attrs: {},
                    content: [
                        {
                            tag: 'list',
                            attrs: {},
                            content: [
                                {
                                    tag: 'user',
                                    attrs: { jid: '123@s.whatsapp.net' },
                                    content: [
                                        {
                                            tag: 'devices',
                                            attrs: {},
                                            content: [
                                                {
                                                    tag: 'device-list',
                                                    attrs: {},
                                                    content: [
                                                        { tag: 'device', attrs: { id: '0' } },
                                                        { tag: 'device', attrs: { id: '2' } },
                                                    ],
                                                },
                                            ],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
            ],
        }

        const parsed = parseDeviceListResponse(response, ['123@s.whatsapp.net'])
        assert.equal(parsed.length, 1)
        assert.equal(parsed[0]!.userJid, '123@s.whatsapp.net')
        assert.equal(parsed[0]!.devices.length, 2)
        assert.equal(parsed[0]!.devices[0]!.jid, '123@s.whatsapp.net')
        assert.equal(parsed[0]!.devices[1]!.jid, '123:2@s.whatsapp.net')
    })

    it('ignores users that were not requested', () => {
        const response: BinaryNode = {
            tag: 'iq',
            attrs: { type: 'result' },
            content: [
                {
                    tag: 'usync',
                    attrs: {},
                    content: [
                        {
                            tag: 'list',
                            attrs: {},
                            content: [
                                {
                                    tag: 'user',
                                    attrs: { jid: 'other@s.whatsapp.net' },
                                    content: [],
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        assert.equal(parseDeviceListResponse(response, ['123@s.whatsapp.net']).length, 0)
    })

    it('caches device lists', () => {
        const store = new DeviceListStore()
        assert.equal(store.get('123@s.whatsapp.net'), undefined)
        store.set({
            userJid: '123@s.whatsapp.net',
            devices: [{ deviceId: 0, jid: '123@s.whatsapp.net' }],
            updatedAtMs: Date.now(),
        })
        assert.equal(store.get('123@s.whatsapp.net')?.length, 1)
        assert.equal(store.size, 1)
        store.remove('123@s.whatsapp.net')
        assert.equal(store.get('123@s.whatsapp.net'), undefined)
    })

    it('expires a stale cache entry', () => {
        const store = new DeviceListStore({ ttlMs: 0 })
        store.set({
            userJid: '123@s.whatsapp.net',
            devices: [{ deviceId: 0, jid: '123@s.whatsapp.net' }],
            updatedAtMs: Date.now() - 1000,
        })
        assert.equal(store.get('123@s.whatsapp.net'), undefined)
    })

    it('deduplicates device ids', () => {
        const response: BinaryNode = {
            tag: 'iq',
            attrs: { type: 'result' },
            content: [
                {
                    tag: 'usync',
                    attrs: {},
                    content: [
                        {
                            tag: 'list',
                            attrs: {},
                            content: [
                                {
                                    tag: 'user',
                                    attrs: { jid: '123@s.whatsapp.net' },
                                    content: [
                                        {
                                            tag: 'devices',
                                            attrs: {},
                                            content: [
                                                {
                                                    tag: 'device-list',
                                                    attrs: {},
                                                    content: [
                                                        { tag: 'device', attrs: { id: '0' } },
                                                        { tag: 'device', attrs: { id: '0' } },
                                                        { tag: 'device', attrs: { id: 'x' } },
                                                    ],
                                                },
                                            ],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        const parsed = parseDeviceListResponse(response, ['123@s.whatsapp.net'])
        assert.equal(parsed[0]!.devices.length, 1)
    })
})
