/**
 * Device-attestation tests.
 *
 * When the server confirms a pairing, it hands out a *signed device
 * identity*: the account's signature over the details of this device,
 * sealed with the secret both sides derived during the handshake. The
 * client has to verify the seal, check the signature and answer with its
 * own signature — the server expects that answer.
 *
 * The tests below build the very payload the server sends and check that
 * the answer the client produces verifies against the account key.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    ADV_PREFIX_ACCOUNT_SIGNATURE,
    ADV_PREFIX_DEVICE_SIGNATURE,
    computeAdvIdentityHmac,
    generateDeviceSignature,
    parseAdvSignedIdentity,
    parseAdvSignedIdentityHmac,
    verifyDeviceIdentityAccountSignature,
} from '../src/signal/attestation.js'
import {
    concat,
    generateX25519KeyPair,
    hmacSha256,
    toRawPublicKey,
} from '../src/crypto/primitives.js'
import { xeddsaSign, xeddsaVerify } from '../src/crypto/curve25519.js'
import { decode, encode } from '../src/proto/codec.js'

/** The device details the account signs. */
const DEVICE_DETAILS = encode('ADVDeviceIdentity', {
    rawId: 1,
    timestamp: 1700000000,
    keyIndex: 7,
    accountType: 0,
    deviceType: 0,
})

describe('device attestation', () => {
    it('uses the domain separators of the protocol', () => {
        assert.deepEqual(ADV_PREFIX_ACCOUNT_SIGNATURE, new Uint8Array([6, 0]))
        assert.deepEqual(ADV_PREFIX_DEVICE_SIGNATURE, new Uint8Array([6, 1]))
    })

    it('seals the signed identity with the shared secret', () => {
        const secret = new Uint8Array(32).fill(9)
        const hmac = computeAdvIdentityHmac(secret, DEVICE_DETAILS)
        assert.deepEqual(hmac, hmacSha256(secret, DEVICE_DETAILS))
    })

    it('verifies the account signature over the device details', () => {
        const account = generateX25519KeyPair()
        const identity = new Uint8Array(32).fill(3)

        const signature = xeddsaSign(
            account.privateKey,
            concat(ADV_PREFIX_ACCOUNT_SIGNATURE, DEVICE_DETAILS, identity),
        )

        assert.ok(
            verifyDeviceIdentityAccountSignature(
                DEVICE_DETAILS,
                signature,
                identity,
                account.publicKey,
            ),
        )
    })

    it('rejects an account signature over the wrong identity key', () => {
        const account = generateX25519KeyPair()
        const signature = xeddsaSign(
            account.privateKey,
            concat(ADV_PREFIX_ACCOUNT_SIGNATURE, DEVICE_DETAILS, new Uint8Array(32).fill(3)),
        )

        assert.equal(
            verifyDeviceIdentityAccountSignature(
                DEVICE_DETAILS,
                signature,
                new Uint8Array(32).fill(4),
                account.publicKey,
            ),
            false,
        )
    })

    it('signs with the raw identity key', () => {
        const account = generateX25519KeyPair()
        const identity = generateX25519KeyPair()
        // The key store keeps the serialized form — 33 bytes with the
        // version byte — while the protocol signs the raw key.
        const serialized = new Uint8Array(33)
        serialized[0] = 5
        serialized.set(identity.publicKey, 1)

        const signature = generateDeviceSignature(
            DEVICE_DETAILS,
            { pubKey: serialized, privKey: identity.privateKey },
            account.publicKey,
        )

        assert.ok(
            xeddsaVerify(
                identity.publicKey,
                concat(
                    ADV_PREFIX_DEVICE_SIGNATURE,
                    DEVICE_DETAILS,
                    toRawPublicKey(serialized),
                    account.publicKey,
                ),
                signature,
            ),
        )
    })

    it('round-trips the sealed identity', () => {
        const secret = new Uint8Array(32).fill(4)
        const account = generateX25519KeyPair()
        const identity = new Uint8Array(32).fill(6)

        const accountSignature = xeddsaSign(
            account.privateKey,
            concat(ADV_PREFIX_ACCOUNT_SIGNATURE, DEVICE_DETAILS, identity),
        )
        const signed = encode('ADVSignedDeviceIdentity', {
            details: DEVICE_DETAILS,
            accountSignatureKey: account.publicKey,
            accountSignature,
        })
        const sealed = encode('ADVSignedDeviceIdentityHMAC', {
            details: signed,
            hmac: computeAdvIdentityHmac(secret, signed),
            accountType: 0,
        })

        const parsedSealed = parseAdvSignedIdentityHmac(sealed)
        assert.deepEqual(parsedSealed.details, signed)
        assert.equal(parsedSealed.accountType, 0)

        const parsed = parseAdvSignedIdentity(parsedSealed.details)
        assert.deepEqual(parsed.details, DEVICE_DETAILS)
        assert.deepEqual(parsed.accountSignatureKey, account.publicKey)
        assert.deepEqual(parsed.accountSignature, accountSignature)

        const decoded = decode('ADVSignedDeviceIdentity', signed)
        assert.deepEqual(decoded.details, DEVICE_DETAILS)
    })
})
