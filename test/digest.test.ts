/**
 * Signal key-digest tests.
 *
 * The server keeps a digest of the key bundle it holds for a device. The
 * client compares it with its own state to detect a drift, which is what
 * the official client does in `WAWebDigestKeyJob`.
 */

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { describe, it } from 'node:test'

import {
    buildDigestIq,
    computeKeyBundleHash,
    parseDigestResponse,
    validateKeyBundleDigest,
} from '../src/signal/digest.js'
import { intToBytes } from '../src/signal/api.js'
import {
    SignalKeyStore,
    generatePreKeyPair,
    generateRegistrationInfo,
    generateSignedPreKey,
} from '../src/signal/keys.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

/** Strips the `0x05` prefix from a serialized public key. */
function raw(key: Uint8Array): Uint8Array {
    return key.length === 33 ? key.subarray(1) : key
}

/** Builds a digest response the way the server answers. */
function buildDigestResponse(
    registrationId: number,
    identity: Uint8Array,
    signedKeyId: number,
    signedKeyValue: Uint8Array,
    signature: Uint8Array,
    preKeyIds: number[],
    hash: Uint8Array,
): BinaryNode {
    return {
        tag: 'iq',
        attrs: { id: 'digest-1', type: 'result' },
        content: [
            {
                tag: 'digest',
                attrs: {},
                content: [
                    { tag: 'registration', attrs: {}, content: intToBytes(4, registrationId) },
                    { tag: 'type', attrs: {}, content: new Uint8Array([5]) },
                    { tag: 'identity', attrs: {}, content: identity },
                    {
                        tag: 'skey',
                        attrs: {},
                        content: [
                            { tag: 'id', attrs: {}, content: intToBytes(3, signedKeyId) },
                            { tag: 'value', attrs: {}, content: signedKeyValue },
                            { tag: 'signature', attrs: {}, content: signature },
                        ],
                    },
                    {
                        tag: 'list',
                        attrs: {},
                        content: preKeyIds.map((id) => ({
                            tag: 'key',
                            attrs: {},
                            content: intToBytes(3, id),
                        })),
                    },
                    { tag: 'hash', attrs: {}, content: hash },
                ],
            },
        ],
    }
}

describe('signal key digest', () => {
    it('builds the digest query the way the official client does', () => {
        const iq = buildDigestIq()
        assert.equal(iq.tag, 'iq')
        assert.equal(iq.attrs.type, 'get')
        assert.equal(iq.attrs.xmlns, 'encrypt')
        assert.equal(iq.attrs.to, 's.whatsapp.net')
        const content = iq.content as BinaryNode[]
        assert.equal(content.length, 1)
        assert.equal(content[0]?.tag, 'digest')
    })

    it('parses the digest the server answers with', () => {
        const registration = generateRegistrationInfo()
        const signed = generateSignedPreKey(1, registration.identityKeyPair.privKey)
        const preKey = generatePreKeyPair(7)
        const hash = computeKeyBundleHash(registration, signed, [preKey])

        const response = buildDigestResponse(
            registration.registrationId,
            raw(registration.identityKeyPair.pubKey),
            signed.keyId,
            raw(signed.keyPair.pubKey),
            signed.signature,
            [preKey.keyId],
            hash,
        )

        const digest = parseDigestResponse(response)
        assert.equal(digest.registrationId, registration.registrationId)
        assert.equal(digest.keyBundleType, 5)
        assert.deepEqual(digest.identity, raw(registration.identityKeyPair.pubKey))
        assert.equal(digest.signedKey.id, signed.keyId)
        assert.deepEqual(digest.signedKey.publicKey, raw(signed.keyPair.pubKey))
        assert.deepEqual(digest.signedKey.signature, signed.signature)
        assert.deepEqual(digest.preKeyIds, [preKey.keyId])
        assert.deepEqual(digest.hash, hash)
    })

    it('hashes the bundle the way the official client does', () => {
        const registration = generateRegistrationInfo()
        const signed = generateSignedPreKey(1, registration.identityKeyPair.privKey)
        const first = generatePreKeyPair(3)
        const second = generatePreKeyPair(4)

        const expected = createHash('sha1')
            .update(raw(registration.identityKeyPair.pubKey))
            .update(raw(signed.keyPair.pubKey))
            .update(signed.signature)
            .update(raw(first.keyPair.pubKey))
            .update(raw(second.keyPair.pubKey))
            .digest()

        const hash = computeKeyBundleHash(registration, signed, [first, second])
        assert.deepEqual(hash, new Uint8Array(expected))
        assert.equal(hash.length, 20)
    })

    it('accepts a bundle that matches the server digest', () => {
        const store = new SignalKeyStore()
        const registration = generateRegistrationInfo()
        store.setRegistrationInfo(registration)
        const signed = generateSignedPreKey(store.allocateSignedPreKeyId(), registration.identityKeyPair.privKey)
        store.setSignedPreKey(signed)
        const preKey = generatePreKeyPair(11)
        store.addPreKey(preKey)

        const digest = {
            registrationId: registration.registrationId,
            keyBundleType: 5,
            identity: raw(registration.identityKeyPair.pubKey),
            signedKey: {
                id: signed.keyId,
                publicKey: raw(signed.keyPair.pubKey),
                signature: signed.signature,
            },
            preKeyIds: [preKey.keyId],
            hash: computeKeyBundleHash(registration, signed, [preKey]),
        }

        const validation = validateKeyBundleDigest(
            digest,
            registration,
            signed,
            (id) => store.getPreKey(id),
        )
        assert.equal(validation.valid, true)
        assert.equal(validation.reason, 'ok')
        assert.equal(validation.shouldReupload, false)
        assert.equal(validation.preKeyCount, 1)
    })

    it('detects a registration mismatch', () => {
        const store = new SignalKeyStore()
        const registration = generateRegistrationInfo()
        store.setRegistrationInfo(registration)
        const signed = generateSignedPreKey(1, registration.identityKeyPair.privKey)
        store.setSignedPreKey(signed)

        const validation = validateKeyBundleDigest(
            {
                registrationId: registration.registrationId + 1,
                keyBundleType: 5,
                identity: raw(registration.identityKeyPair.pubKey),
                signedKey: {
                    id: signed.keyId,
                    publicKey: raw(signed.keyPair.pubKey),
                    signature: signed.signature,
                },
                preKeyIds: [],
                hash: new Uint8Array(20),
            },
            registration,
            signed,
            (id) => store.getPreKey(id),
        )
        assert.equal(validation.valid, false)
        assert.equal(validation.reason, 'registration_mismatch')
        assert.equal(validation.shouldReupload, true)
    })

    it('detects a missing local pre-key', () => {
        const store = new SignalKeyStore()
        const registration = generateRegistrationInfo()
        store.setRegistrationInfo(registration)
        const signed = generateSignedPreKey(1, registration.identityKeyPair.privKey)
        store.setSignedPreKey(signed)

        const validation = validateKeyBundleDigest(
            {
                registrationId: registration.registrationId,
                keyBundleType: 5,
                identity: raw(registration.identityKeyPair.pubKey),
                signedKey: {
                    id: signed.keyId,
                    publicKey: raw(signed.keyPair.pubKey),
                    signature: signed.signature,
                },
                preKeyIds: [99],
                hash: new Uint8Array(20),
            },
            registration,
            signed,
            (id) => store.getPreKey(id),
        )
        assert.equal(validation.valid, false)
        assert.equal(validation.reason, 'missing_local_prekey')
        assert.equal(validation.shouldReupload, true)
    })

    it('detects a hash mismatch', () => {
        const store = new SignalKeyStore()
        const registration = generateRegistrationInfo()
        store.setRegistrationInfo(registration)
        const signed = generateSignedPreKey(1, registration.identityKeyPair.privKey)
        store.setSignedPreKey(signed)
        const preKey = generatePreKeyPair(5)
        store.addPreKey(preKey)

        const hash = computeKeyBundleHash(registration, signed, [preKey])
        hash[0] = hash[0]! ^ 0xff

        const validation = validateKeyBundleDigest(
            {
                registrationId: registration.registrationId,
                keyBundleType: 5,
                identity: raw(registration.identityKeyPair.pubKey),
                signedKey: {
                    id: signed.keyId,
                    publicKey: raw(signed.keyPair.pubKey),
                    signature: signed.signature,
                },
                preKeyIds: [preKey.keyId],
                hash,
            },
            registration,
            signed,
            (id) => store.getPreKey(id),
        )
        assert.equal(validation.valid, false)
        assert.equal(validation.reason, 'hash_mismatch')
        assert.equal(validation.shouldReupload, true)
    })

    it('does not re-upload for an unknown key bundle type', () => {
        const store = new SignalKeyStore()
        const registration = generateRegistrationInfo()
        store.setRegistrationInfo(registration)
        const signed = generateSignedPreKey(1, registration.identityKeyPair.privKey)
        store.setSignedPreKey(signed)

        const validation = validateKeyBundleDigest(
            {
                registrationId: registration.registrationId,
                keyBundleType: 99,
                identity: raw(registration.identityKeyPair.pubKey),
                signedKey: {
                    id: signed.keyId,
                    publicKey: raw(signed.keyPair.pubKey),
                    signature: signed.signature,
                },
                preKeyIds: [],
                hash: new Uint8Array(20),
            },
            registration,
            signed,
            (id) => store.getPreKey(id),
        )
        assert.equal(validation.valid, false)
        assert.equal(validation.reason, 'unsupported_key_bundle_type')
        assert.equal(validation.shouldReupload, false)
    })
})
