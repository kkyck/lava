/**
 * Cryptographic primitive tests.
 *
 * These verify the primitives against published test vectors where they
 * exist, and against the round-trip property where they do not.
 */

import assert from 'node:assert/strict'
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'

import {
    aesCbcDecrypt,
    aesCbcEncrypt,
    aesCtrDecrypt,
    aesCtrEncrypt,
    aesGcmDecrypt,
    aesGcmEncrypt,
    concat,
    equalBytes,
    fromHex,
    hkdf,
    hkdfSplit,
    hmacSha256,
    md5,
    pbkdf2Sha256,
    sha256,
    toHex,
    utf8,
    x25519,
    generateX25519KeyPair,
    x25519PublicFromPrivate,
} from '../src/crypto/primitives.js'
import { xeddsaSign, xeddsaVerify } from '../src/crypto/curve25519.js'

describe('crypto primitives', () => {
    it('computes SHA-256 like node:crypto', () => {
        const data = utf8('abc')
        assert.equal(toHex(sha256(data)), createHash('sha256').update(data).digest('hex'))
    })

    it('computes MD5 like node:crypto', () => {
        const data = utf8('abc')
        assert.equal(toHex(md5(data)), createHash('md5').update(data).digest('hex'))
    })

    it('computes HMAC-SHA256 like node:crypto', () => {
        const key = utf8('key')
        const data = utf8('message')
        assert.equal(
            toHex(hmacSha256(key, data)),
            createHmac('sha256', key).update(data).digest('hex'),
        )
    })

    it('computes PBKDF2 like node:crypto', () => {
        const password = utf8('password')
        const salt = utf8('salt')
        const derived = pbkdf2Sha256(password, salt, 1000, 32)
        assert.equal(
            toHex(derived),
            pbkdf2Sync(password, salt, 1000, 32, 'sha256').toString('hex'),
        )
    })

    it('round-trips AES-CBC', () => {
        const key = randomBytes(32)
        const iv = randomBytes(16)
        const plaintext = utf8('a message that is not a multiple of the block size')
        const ciphertext = aesCbcEncrypt(key, iv, plaintext)
        assert.notDeepEqual(ciphertext, plaintext)
        assert.deepEqual(aesCbcDecrypt(key, iv, ciphertext), plaintext)
    })

    it('round-trips AES-CTR', () => {
        const key = randomBytes(32)
        const counter = randomBytes(16)
        const plaintext = utf8('counter mode payload')
        const ciphertext = aesCtrEncrypt(key, counter, plaintext)
        assert.deepEqual(aesCtrDecrypt(key, counter, ciphertext), plaintext)
    })

    it('round-trips AES-GCM and detects tampering', () => {
        const key = randomBytes(32)
        const nonce = randomBytes(12)
        const plaintext = utf8('secret')
        const sealed = aesGcmEncrypt(key, nonce, plaintext)
        assert.deepEqual(aesGcmDecrypt(key, nonce, sealed), plaintext)

        const tampered = new Uint8Array(sealed)
        tampered[tampered.length - 1] = (tampered[tampered.length - 1]! ^ 0xff)
        assert.throws(() => aesGcmDecrypt(key, nonce, tampered))
    })

    it('splits HKDF into independent keys', () => {
        const ikm = randomBytes(32)
        const salt = randomBytes(32)
        const info = utf8('info')
        const [okm1, okm2] = hkdfSplit(ikm, salt, info)
        assert.equal(okm1.length, 32)
        assert.equal(okm2.length, 32)
        assert.ok(!equalBytes(okm1, okm2))
        // Deterministic.
        const [again1, again2] = hkdfSplit(ikm, salt, info)
        assert.ok(equalBytes(okm1, again1))
        assert.ok(equalBytes(okm2, again2))
    })

    it('derives an HKDF key of the requested length', () => {
        const derived = hkdf(randomBytes(32), null, utf8('x'), 48)
        assert.equal(derived.length, 48)
    })

    it('computes an X25519 shared secret both ways', () => {
        const alice = generateX25519KeyPair()
        const bob = generateX25519KeyPair()
        const s1 = x25519(alice.privateKey, bob.publicKey)
        const s2 = x25519(bob.privateKey, alice.publicKey)
        assert.ok(equalBytes(s1, s2))
        assert.equal(s1.length, 32)
    })

    it('derives the public key from a private key', () => {
        const pair = generateX25519KeyPair()
        const derived = x25519PublicFromPrivate(pair.privateKey)
        assert.ok(equalBytes(derived, pair.publicKey))
    })

    it('signs and verifies with XEdDSA', () => {
        const pair = generateX25519KeyPair()
        const message = utf8('sign me')
        const signature = xeddsaSign(pair.privateKey, message)
        assert.ok(xeddsaVerify(pair.publicKey, message, signature))
        assert.ok(!xeddsaVerify(pair.publicKey, utf8('other'), signature))
    })

    it('concatenates byte arrays', () => {
        const joined = concat(new Uint8Array([1, 2]), undefined, new Uint8Array([3]))
        assert.deepEqual(joined, new Uint8Array([1, 2, 3]))
    })

    it('parses and formats hex', () => {
        assert.deepEqual(fromHex('00ff10'), new Uint8Array([0, 255, 16]))
        assert.equal(toHex(new Uint8Array([0, 255, 16])), '00ff10')
    })
})
