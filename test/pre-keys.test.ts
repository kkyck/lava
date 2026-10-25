/**
 * Pre-key store tests.
 *
 * The pre-key lifecycle is the part of the Signal protocol that a server
 * watches closely: the ids must be unique and sequential, the upload cursor
 * must never move backwards, and the signed pre-keys live in their own id
 * namespace. The tests below pin down the semantics the official clients
 * implement.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    SignalKeyStore,
    generatePreKeyPair,
    generateRegistrationInfo,
    generateSignedPreKey,
    MAX_RETAINED_PRE_KEYS,
} from '../src/signal/keys.js'

/** Builds a key store with a registration and a signed pre-key. */
function makeStore(): SignalKeyStore {
    const store = new SignalKeyStore()
    const registration = generateRegistrationInfo()
    store.setRegistrationInfo(registration)
    store.setSignedPreKey(
        generateSignedPreKey(store.allocateSignedPreKeyId(), registration.identityKeyPair.privKey),
    )
    return store
}

describe('pre-key store', () => {
    it('keeps the signed pre-key ids in their own namespace', () => {
        const store = makeStore()

        // The signed pre-key took id 1, so the one-time pre-keys start at
        // their own id 1 as well — the two namespaces do not interfere.
        assert.equal(store.getSignedPreKey()?.keyId, 1)
        assert.equal(store.allocatePreKeyId(), 1)
        assert.equal(store.getNextSignedPreKeyId(), 2)

        // The next signed pre-key continues in the signed namespace.
        assert.equal(store.allocateSignedPreKeyId(), 2)
        assert.equal(store.getNextSignedPreKeyId(), 3)
    })

    it('never hands out a signed pre-key id twice', () => {
        const store = makeStore()
        const ids = new Set<number>()
        for (let i = 0; i < 16; i += 1) {
            const id = store.allocateSignedPreKeyId()
            assert.equal(ids.has(id), false)
            ids.add(id)
        }
        assert.equal(ids.size, 16)
    })

    it('filters the pre-keys by range before applying the limit', () => {
        const store = makeStore()
        for (let id = 1; id <= 10; id += 1) {
            store.addPreKey(generatePreKeyPair(id))
        }

        // The filter runs first: the oldest key is skipped and the newest
        // ones are returned, even though the limit is smaller than the pool.
        const selected = store.getPreKeysByRange(6, 3)
        assert.deepEqual(
            selected.map((record) => record.keyId),
            [6, 7, 8],
        )
    })

    it('returns the oldest pre-keys when no range is given', () => {
        const store = makeStore()
        for (let id = 1; id <= 5; id += 1) {
            store.addPreKey(generatePreKeyPair(id))
        }
        assert.deepEqual(
            store.listPreKeys(2).map((record) => record.keyId),
            [1, 2],
        )
    })

    it('generates the missing pre-keys on demand', () => {
        const store = makeStore()
        const batch = store.getOrGenPreKeys(4, generatePreKeyPair)
        assert.deepEqual(
            batch.map((record) => record.keyId),
            [1, 2, 3, 4],
        )
        assert.equal(store.getPreKeyCount(), 4)

        // The pool already holds enough keys, so nothing new is generated.
        const second = store.getOrGenPreKeys(4, generatePreKeyPair)
        assert.deepEqual(
            second.map((record) => record.keyId),
            [1, 2, 3, 4],
        )
        assert.equal(store.getPreKeyCount(), 4)
    })

    it('generates the missing pre-keys after the cursor moved on', () => {
        const store = makeStore()
        store.getOrGenPreKeys(3, generatePreKeyPair)
        store.markKeyAsUploaded(3)

        // The upload cursor sits at 4, so the next batch starts there.
        const batch = store.getOrGenPreKeys(3, generatePreKeyPair)
        assert.deepEqual(
            batch.map((record) => record.keyId),
            [4, 5, 6],
        )
    })

    it('rejects an invalid pre-key count', () => {
        const store = makeStore()
        assert.throws(() => store.getOrGenPreKeys(0, generatePreKeyPair), /invalid pre-key count/)
        assert.throws(() => store.getOrGenPreKeys(-1, generatePreKeyPair), /invalid pre-key count/)
    })

    it('moves the upload cursor forward and never backwards', () => {
        const store = makeStore()
        store.getOrGenPreKeys(5, generatePreKeyPair)

        store.markKeyAsUploaded(3)
        assert.equal(store.getFirstUnuploadedPreKeyId(), 4)

        // A stale id must not move the cursor back.
        store.markKeyAsUploaded(1)
        assert.equal(store.getFirstUnuploadedPreKeyId(), 4)
    })

    it('rejects an out-of-boundary upload cursor', () => {
        const store = makeStore()
        store.getOrGenPreKeys(2, generatePreKeyPair)

        // The next id is 3, so 3 is already out of bounds.
        assert.throws(() => store.markKeyAsUploaded(3), /out of boundary/)
        assert.throws(() => store.markKeyAsUploaded(-1), /out of boundary/)
    })

    it('remembers whether the server holds a batch of pre-keys', () => {
        const store = makeStore()
        assert.equal(store.getServerHasPreKeys(), false)
        store.setServerHasPreKeys(true)
        assert.equal(store.getServerHasPreKeys(), true)
    })

    it('drops the oldest uploaded pre-keys when the pool grows too large', () => {
        const store = makeStore()
        store.getOrGenPreKeys(10, generatePreKeyPair)
        store.markKeyAsUploaded(10)

        const dropped = store.prunePreKeys(4)
        assert.deepEqual(dropped, [1, 2, 3, 4, 5, 6])
        assert.equal(store.getPreKeyCount(), 4)

        // The newest keys are the ones that were uploaded last.
        assert.deepEqual(
            store.listPreKeys().map((record) => record.keyId),
            [7, 8, 9, 10],
        )
    })

    it('never drops a pre-key that was not uploaded yet', () => {
        const store = makeStore()
        store.getOrGenPreKeys(10, generatePreKeyPair)
        store.markKeyAsUploaded(4)

        const dropped = store.prunePreKeys(6)
        assert.deepEqual(dropped, [1, 2, 3, 4])
        assert.equal(store.getPreKeyCount(), 6)

        // Everything that is left is still waiting for the server.
        for (const record of store.listPreKeys()) {
            assert.ok(record.keyId >= 5)
        }
    })

    it('does nothing when the pool is small enough', () => {
        const store = makeStore()
        store.getOrGenPreKeys(3, generatePreKeyPair)
        assert.deepEqual(store.prunePreKeys(10), [])
        assert.equal(store.getPreKeyCount(), 3)
    })

    it('bounds the pool at the documented maximum', () => {
        assert.equal(MAX_RETAINED_PRE_KEYS, 4096)
    })

    it('restores the counters from a snapshot', () => {
        const store = makeStore()
        store.getOrGenPreKeys(3, generatePreKeyPair)
        store.markKeyAsUploaded(2)
        store.setServerHasPreKeys(true)

        const snapshot = store.export()

        const restored = new SignalKeyStore()
        restored.import(snapshot)

        assert.equal(restored.getFirstUnuploadedPreKeyId(), 3)
        assert.equal(restored.getNextPreKeyId(), 4)
        assert.equal(restored.getNextSignedPreKeyId(), 2)
        assert.equal(restored.getServerHasPreKeys(), true)
        assert.equal(restored.getPreKeyCount(), 3)
    })

    it('never restores a counter to an older value', () => {
        const store = makeStore()
        store.getOrGenPreKeys(3, generatePreKeyPair)
        store.markKeyAsUploaded(2)
        store.setFirstUnuploadedPreKeyId(1)
        store.setNextPreKeyId(1)
        store.setNextSignedPreKeyId(1)

        assert.equal(store.getFirstUnuploadedPreKeyId(), 3)
        assert.equal(store.getNextPreKeyId(), 4)
        assert.equal(store.getNextSignedPreKeyId(), 2)
    })
})
