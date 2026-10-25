/**
 * App-state tests.
 *
 * The app state is the part of the protocol that keeps the chat list, the
 * contacts and the labels of an account in sync between its devices. The
 * server never sees the state itself: every record is encrypted with a sync
 * key and MACed, and a digest (the LT-hash) proves that two devices hold the
 * same collection without the server reading any of it.
 *
 * The tests below pin down the parts that must not drift — the key
 * derivation, the MACs, the digest arithmetic and the shape of the
 * exchange with the server.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    APP_STATE_COLLECTIONS,
    APP_STATE_COLLECTION_STATES,
    APP_STATE_EMPTY_LT_HASH,
    APP_STATE_LT_HASH_SIZE,
} from '../src/appstate/constants.js'
import { AppStateCrypto } from '../src/appstate/crypto.js'
import {
    buildSyncKeyId,
    generateSyncKey,
    pickActiveSyncKey,
    syncKeyDeviceId,
    syncKeyEpoch,
} from '../src/appstate/keys.js'
import { AppStateStore } from '../src/appstate/store.js'
import {
    AppStateSyncClient,
    parseCollectionState,
    type AppStateCollectionPayload,
} from '../src/appstate/sync.js'
import { decode, encode } from '../src/proto/codec.js'
import { toHex } from '../src/crypto/primitives.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

const KEY_DATA = new Uint8Array(32).fill(7)
const KEY_ID = buildSyncKeyId(1, 2)

/** Builds a sync client backed by an in-memory store. */
function makeClient(
    options: {
        store?: AppStateStore
        mobilePrimary?: boolean
        answer?: (node: BinaryNode) => BinaryNode
        downloadExternalBlob?: (
            collection: string,
            kind: 'snapshot' | 'patch',
            reference: unknown,
        ) => Promise<Uint8Array>
        onMissingKeys?: (keyIds: readonly Uint8Array[]) => void | Promise<void>
    } = {},
): { client: AppStateSyncClient; store: AppStateStore } {
    const store = options.store ?? new AppStateStore()
    const client = new AppStateSyncClient({
        query: async (node) =>
            options.answer
                ? options.answer(node)
                : { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } },
        store,
        mobilePrimary: options.mobilePrimary ?? true,
        ...(options.downloadExternalBlob
            ? { downloadExternalBlob: options.downloadExternalBlob as never }
            : {}),
        ...(options.onMissingKeys ? { onMissingKeys: options.onMissingKeys } : {}),
    })
    return { client, store }
}

/** Builds a `<collection>` node. */
function collectionNode(attrs: Record<string, string>, content?: BinaryNode[]): BinaryNode {
    return {
        tag: 'collection',
        attrs,
        content,
    }
}

describe('app-state crypto', () => {
    it('derives the five keys of a sync key', () => {
        const crypto = new AppStateCrypto()
        const keys = crypto.deriveKeys(KEY_DATA)
        assert.equal(keys.indexHmacKey.length, 32)
        assert.equal(keys.valueEncryptionAesKey.length, 32)
        assert.equal(keys.valueMacHmacKey.length, 32)
        assert.equal(keys.snapshotMacHmacKey.length, 32)
        assert.equal(keys.patchMacHmacKey.length, 32)
    })

    it('derives the same keys every time', () => {
        const crypto = new AppStateCrypto()
        const first = crypto.deriveKeys(KEY_DATA)
        const second = crypto.deriveKeys(KEY_DATA)
        assert.equal(toHex(first.valueEncryptionAesKey), toHex(second.valueEncryptionAesKey))
    })

    it('encrypts and decrypts a mutation', () => {
        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            index: 'the-index',
            value: { pushNameSetting: { name: 'Lava' } },
            version: 7,
        })
        const decrypted = crypto.decryptMutation({
            operation: 'set',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            indexMac: encrypted.indexMac,
            valueBlob: encrypted.valueBlob,
        })
        assert.equal(decrypted.index, 'the-index')
        assert.equal(decrypted.version, 7)
        assert.deepEqual(decrypted.value, { pushNameSetting: { name: 'Lava' } })
    })

    it('encrypts the value before the MAC covers it', () => {
        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            index: 'the-index',
            value: { pushNameSetting: { name: 'Lava' } },
            version: 7,
        })
        // The blob is the IV, the ciphertext and the value MAC.
        assert.ok(encrypted.valueBlob.length > 16 + 32)
        assert.equal(
            toHex(encrypted.valueBlob.subarray(encrypted.valueBlob.length - 32)),
            toHex(encrypted.valueMac),
        )
    })

    it('binds the MAC to the operation', () => {
        const crypto = new AppStateCrypto()
        const set = crypto.encryptMutation({
            operation: 'set',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            index: 'the-index',
            version: 7,
        })
        const remove = crypto.encryptMutation({
            operation: 'remove',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            index: 'the-index',
            version: 7,
        })
        // The index MAC only covers the index, so it is the same; the value
        // MAC covers the operation as well, so it differs.
        assert.equal(toHex(set.indexMac), toHex(remove.indexMac))
        assert.notEqual(toHex(set.valueMac), toHex(remove.valueMac))
    })

    it('rejects a tampered value', () => {
        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            index: 'the-index',
            version: 7,
        })
        const tampered = Uint8Array.from(encrypted.valueBlob)
        tampered[20] = tampered[20]! ^ 0xff
        assert.throws(
            () =>
                crypto.decryptMutation({
                    operation: 'set',
                    keyId: KEY_ID,
                    keyData: KEY_DATA,
                    indexMac: encrypted.indexMac,
                    valueBlob: tampered,
                }),
            /MAC mismatch/,
        )
    })

    it('rejects a tampered index MAC', () => {
        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: KEY_ID,
            keyData: KEY_DATA,
            index: 'the-index',
            version: 7,
        })
        const tampered = Uint8Array.from(encrypted.indexMac)
        tampered[0] = tampered[0]! ^ 0xff
        assert.throws(
            () =>
                crypto.decryptMutation({
                    operation: 'set',
                    keyId: KEY_ID,
                    keyData: KEY_DATA,
                    indexMac: tampered,
                    valueBlob: encrypted.valueBlob,
                }),
            /index MAC mismatch/,
        )
    })

    it('rejects a value blob that is too short', () => {
        const crypto = new AppStateCrypto()
        assert.throws(
            () =>
                crypto.decryptMutation({
                    operation: 'set',
                    keyId: KEY_ID,
                    keyData: KEY_DATA,
                    indexMac: new Uint8Array(32),
                    valueBlob: new Uint8Array(8),
                }),
            /invalid mutation value blob/,
        )
    })

    it('adds and subtracts value MACs in the LT-hash', () => {
        const crypto = new AppStateCrypto()
        const macA = new Uint8Array(32).fill(1)
        const macB = new Uint8Array(32).fill(2)

        const added = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [macA, macB])
        assert.equal(added.length, APP_STATE_LT_HASH_SIZE)
        assert.notEqual(toHex(added), toHex(APP_STATE_EMPTY_LT_HASH))

        // Adding and removing the same MACs cancels out.
        const back = crypto.ltHashSubtract(added, [macA, macB])
        assert.equal(toHex(back), toHex(APP_STATE_EMPTY_LT_HASH))
    })

    it('keeps the digest the same size no matter how many records there are', () => {
        const crypto = new AppStateCrypto()
        const macs = Array.from({ length: 64 }, (_, i) => new Uint8Array(32).fill(i))
        const digest = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, macs)
        assert.equal(digest.length, APP_STATE_LT_HASH_SIZE)
    })

    it('wraps the points of the digest around', () => {
        const crypto = new AppStateCrypto()
        // A value MAC of all ones expands to points that overflow when they
        // are added, so the digest stays inside its 16-bit range.
        const digest = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [new Uint8Array(32).fill(255)])
        for (let i = 0; i < digest.length; i += 2) {
            assert.ok(digest[i + 1]! <= 0xff)
        }
    })

    it('subtracts and adds in one step', () => {
        const crypto = new AppStateCrypto()
        const macA = new Uint8Array(32).fill(3)
        const macB = new Uint8Array(32).fill(4)
        const base = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [macA])
        const { hash, subtractResult } = crypto.ltHashSubtractThenAdd(base, [macB], [macA])
        assert.equal(toHex(subtractResult), toHex(APP_STATE_EMPTY_LT_HASH))
        assert.equal(toHex(hash), toHex(crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [macB])))
    })

    it('computes the snapshot MAC over the digest and the version', () => {
        const crypto = new AppStateCrypto()
        const first = crypto.generateSnapshotMac(KEY_DATA, APP_STATE_EMPTY_LT_HASH, 42, 'regular')
        const second = crypto.generateSnapshotMac(KEY_DATA, APP_STATE_EMPTY_LT_HASH, 42, 'regular')
        const other = crypto.generateSnapshotMac(KEY_DATA, APP_STATE_EMPTY_LT_HASH, 43, 'regular')
        assert.equal(toHex(first), toHex(second))
        assert.notEqual(toHex(first), toHex(other))
    })

    it('binds the patch MAC to the value MACs it carries', () => {
        const crypto = new AppStateCrypto()
        const snapshotMac = crypto.generateSnapshotMac(KEY_DATA, APP_STATE_EMPTY_LT_HASH, 1, 'regular')
        const valueMac = new Uint8Array(32).fill(9)
        const first = crypto.generatePatchMac(KEY_DATA, snapshotMac, [valueMac], 1, 'regular')
        const second = crypto.generatePatchMac(KEY_DATA, snapshotMac, [valueMac], 1, 'regular')
        const third = crypto.generatePatchMac(KEY_DATA, snapshotMac, [], 1, 'regular')
        assert.equal(toHex(first), toHex(second))
        assert.notEqual(toHex(first), toHex(third))
    })
})

describe('app-state keys', () => {
    it('lays the key id out like the official client', () => {
        const id = buildSyncKeyId(3, 0x01020304)
        assert.equal(id.length, 6)
        assert.equal(toHex(id), '000301020304')
        assert.equal(syncKeyDeviceId(id), 3)
        assert.equal(syncKeyEpoch(id), 0x01020304)
    })

    it('reports a short key id as unknown', () => {
        assert.equal(syncKeyDeviceId(new Uint8Array(4)), null)
        assert.equal(syncKeyEpoch(new Uint8Array(4)), -1)
    })

    it('picks the key with the highest epoch', () => {
        const low = { keyId: buildSyncKeyId(0, 1), keyData: KEY_DATA, timestamp: 0 }
        const high = { keyId: buildSyncKeyId(0, 2), keyData: KEY_DATA, timestamp: 0 }
        assert.equal(pickActiveSyncKey([low, high]), high)
        assert.equal(pickActiveSyncKey([high, low]), high)
    })

    it('breaks a tie with the lower device id', () => {
        const first = { keyId: buildSyncKeyId(5, 9), keyData: KEY_DATA, timestamp: 0 }
        const second = { keyId: buildSyncKeyId(2, 9), keyData: KEY_DATA, timestamp: 0 }
        assert.equal(pickActiveSyncKey([first, second]), second)
    })

    it('returns nothing when there is no key', () => {
        assert.equal(pickActiveSyncKey([]), null)
    })

    it('generates a key with a random secret', () => {
        const first = generateSyncKey(1, Date.now())
        const second = generateSyncKey(1, Date.now())
        assert.equal(first.keyId.length, 6)
        assert.equal(first.keyData.length, 32)
        assert.notEqual(toHex(first.keyData), toHex(second.keyData))
    })
})

describe('app-state store', () => {
    it('survives a snapshot round trip', () => {
        const store = new AppStateStore()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        store.setCollectionState('regular', {
            initialized: true,
            version: 12,
            hash: new Uint8Array(128).fill(3),
            indexValueMap: new Map([['aabb', new Uint8Array(32).fill(1)]]),
        })

        const restored = AppStateStore.fromSnapshot(store.toSnapshot())
        assert.equal(restored.listKeys().length, 1)
        assert.equal(toHex(restored.listKeys()[0]!.keyId), toHex(key.keyId))
        assert.equal(toHex(restored.listKeys()[0]!.keyData), toHex(key.keyData))

        const state = restored.getCollectionState('regular')
        assert.equal(state.initialized, true)
        assert.equal(state.version, 12)
        assert.equal(toHex(state.hash), toHex(new Uint8Array(128).fill(3)))
        assert.equal(toHex(state.indexValueMap.get('aabb')!), toHex(new Uint8Array(32).fill(1)))
    })

    it('keeps the newest key when one is imported twice', () => {
        const store = new AppStateStore()
        const key = generateSyncKey(1, 1000)
        assert.equal(store.upsertKeys([key]), 1)
        assert.equal(store.upsertKeys([key]), 0)
        assert.equal(store.listKeys().length, 1)
    })

    it('starts empty', () => {
        const state = new AppStateStore().getCollectionState('regular')
        assert.equal(state.initialized, false)
        assert.equal(state.version, 0)
        assert.equal(state.indexValueMap.size, 0)
    })
})

describe('app-state sync', () => {
    it('builds the IQ the server expects', () => {
        const { client } = makeClient()
        const node = client.buildSyncIqNode([])
        assert.equal(node.tag, 'iq')
        assert.equal(node.attrs.type, 'set')
        assert.equal(node.attrs.xmlns, 'w:sync:app:state')
        assert.equal(node.attrs.to, 's.whatsapp.net')
        const sync = (node.content as BinaryNode[])[0]!
        assert.equal(sync.tag, 'sync')
    })

    it('names the data namespace of the mobile primary', () => {
        const primary = makeClient({ mobilePrimary: true })
        const secondary = makeClient({ mobilePrimary: false })
        const primarySync = (primary.client.buildSyncIqNode([]).content as BinaryNode[])[0]!
        const secondarySync = (secondary.client.buildSyncIqNode([]).content as BinaryNode[])[0]!
        assert.equal(primarySync.attrs.data_namespace, '3')
        assert.equal(secondarySync.attrs.data_namespace, undefined)
    })

    it('asks for a snapshot when the device has no state yet', () => {
        const { client } = makeClient({ mobilePrimary: false })
        const node = client.buildCollectionRequest('regular', [], null)
        assert.equal(node.attrs.name, 'regular')
        assert.equal(node.attrs.version, '0')
        assert.equal(node.attrs.return_snapshot, 'true')
    })

    it('does not ask for a snapshot once the device has state', () => {
        const { client, store } = makeClient({ mobilePrimary: false })
        store.setCollectionState('regular', {
            initialized: true,
            version: 12,
            hash: APP_STATE_EMPTY_LT_HASH,
            indexValueMap: new Map(),
        })
        const node = client.buildCollectionRequest('regular', [], null)
        assert.equal(node.attrs.version, '12')
        assert.equal(node.attrs.return_snapshot, 'false')
    })

    it('reads the state of a collection', () => {
        assert.equal(
            parseCollectionState(collectionNode({ type: 'success' })),
            APP_STATE_COLLECTION_STATES.SUCCESS,
        )
        assert.equal(
            parseCollectionState(collectionNode({ type: 'success', has_more_patches: 'true' })),
            APP_STATE_COLLECTION_STATES.SUCCESS_HAS_MORE,
        )
        assert.equal(
            parseCollectionState(collectionNode({ type: 'success' })),
            APP_STATE_COLLECTION_STATES.SUCCESS,
        )
    })

    it('reads the error of a collection', () => {
        const conflict = collectionNode(
            { type: 'error' },
            [{ tag: 'error', attrs: { code: '409' } }],
        )
        assert.equal(parseCollectionState(conflict), APP_STATE_COLLECTION_STATES.CONFLICT)

        const fatal = collectionNode(
            { type: 'error' },
            [{ tag: 'error', attrs: { code: '400' } }],
        )
        assert.equal(parseCollectionState(fatal), APP_STATE_COLLECTION_STATES.ERROR_FATAL)

        const retry = collectionNode(
            { type: 'error' },
            [{ tag: 'error', attrs: { code: '500' } }],
        )
        assert.equal(parseCollectionState(retry), APP_STATE_COLLECTION_STATES.ERROR_RETRY)
    })

    it('parses the answer of the server', () => {
        const { client } = makeClient()
        const response: BinaryNode = {
            tag: 'iq',
            attrs: { id: '1', type: 'result' },
            content: [
                {
                    tag: 'sync',
                    attrs: {},
                    content: [
                        collectionNode({ name: 'regular', version: '12', type: 'success' }),
                        collectionNode({
                            name: 'regular_low',
                            version: '3',
                            type: 'success',
                            has_more_patches: 'true',
                        }),
                    ],
                },
            ],
        }
        const payloads = client.parseSyncResponse(response)
        assert.equal(payloads.length, 2)
        assert.equal(payloads[0]!.collection, APP_STATE_COLLECTIONS.REGULAR)
        assert.equal(payloads[0]!.version, 12)
        assert.equal(payloads[0]!.state, APP_STATE_COLLECTION_STATES.SUCCESS)
        assert.equal(payloads[1]!.state, APP_STATE_COLLECTION_STATES.SUCCESS_HAS_MORE)
    })

    it('rejects an answer that names an unknown collection', () => {
        const { client } = makeClient()
        const response: BinaryNode = {
            tag: 'iq',
            attrs: { id: '1', type: 'result' },
            content: [
                {
                    tag: 'sync',
                    attrs: {},
                    content: [collectionNode({ name: 'nonsense', version: '1' })],
                },
            ],
        }
        assert.throws(() => client.parseSyncResponse(response), /invalid collection name/)
    })

    it('rejects an answer that carries no sync node', () => {
        const { client } = makeClient()
        assert.throws(
            () => client.parseSyncResponse({ tag: 'iq', attrs: { id: '1', type: 'result' } }),
            /no <sync> node/,
        )
    })

    it('applies a snapshot and recomputes the digest', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])

        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: key.keyId,
            keyData: key.keyData,
            index: 'the-index',
            value: { pushNameSetting: { name: 'Lava' } },
            version: 1,
        })
        const snapshot = encode('SyncdSnapshot', {
            version: { version: 5 },
            records: [
                {
                    index: { blob: encrypted.indexMac },
                    value: { blob: encrypted.valueBlob },
                    keyId: { id: key.keyId },
                },
            ],
            mac: crypto.generateSnapshotMac(
                key.keyData,
                crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [encrypted.valueMac]),
                5,
                'regular',
            ),
            keyId: { id: key.keyId },
        })

        const mutations = client.applySnapshot('regular', decode('SyncdSnapshot', snapshot))
        assert.equal(mutations.length, 1)
        assert.equal(mutations[0]!.index, 'the-index')
        assert.deepEqual(mutations[0]!.value, { pushNameSetting: { name: 'Lava' } })

        const state = store.getCollectionState('regular')
        assert.equal(state.initialized, true)
        assert.equal(state.version, 5)
        assert.equal(state.indexValueMap.size, 1)
        assert.equal(
            toHex(state.hash),
            toHex(crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [encrypted.valueMac])),
        )
    })

    it('refuses a patch that does not follow the local version', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        store.setCollectionState('regular', {
            initialized: true,
            version: 4,
            hash: APP_STATE_EMPTY_LT_HASH,
            indexValueMap: new Map(),
        })
        const patch = encode('SyncdPatch', {
            version: { version: 9 },
            mutations: [],
            snapshotMac: new Uint8Array(32),
            patchMac: new Uint8Array(32),
            keyId: { id: key.keyId },
        })
        assert.throws(
            () => client.applyPatch('regular', decode('SyncdPatch', patch)),
            /patch version mismatch/,
        )
    })

    it('applies a patch and advances the version', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])

        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: key.keyId,
            keyData: key.keyData,
            index: 'the-index',
            value: { pushNameSetting: { name: 'Lava' } },
            version: 1,
        })
        const nextHash = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [encrypted.valueMac])
        const snapshotMac = crypto.generateSnapshotMac(key.keyData, nextHash, 1, 'regular')
        const patchMac = crypto.generatePatchMac(key.keyData, snapshotMac, [encrypted.valueMac], 1, 'regular')

        const patch = encode('SyncdPatch', {
            version: { version: 1 },
            mutations: [
                {
                    operation: 0,
                    record: {
                        index: { blob: encrypted.indexMac },
                        value: { blob: encrypted.valueBlob },
                        keyId: { id: key.keyId },
                    },
                },
            ],
            snapshotMac,
            patchMac,
            keyId: { id: key.keyId },
        })

        const mutations = client.applyPatch('regular', decode('SyncdPatch', patch))
        assert.equal(mutations.length, 1)
        assert.equal(mutations[0]!.source, 'patch')
        assert.equal(store.getCollectionState('regular').version, 1)
        assert.equal(toHex(store.getCollectionState('regular').hash), toHex(nextHash))
    })

    it('rejects a patch whose MAC does not match', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])

        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: key.keyId,
            keyData: key.keyData,
            index: 'the-index',
            version: 1,
        })
        const patch = encode('SyncdPatch', {
            version: { version: 1 },
            mutations: [
                {
                    operation: 0,
                    record: {
                        index: { blob: encrypted.indexMac },
                        value: { blob: encrypted.valueBlob },
                        keyId: { id: key.keyId },
                    },
                },
            ],
            snapshotMac: new Uint8Array(32),
            patchMac: new Uint8Array(32).fill(9),
            keyId: { id: key.keyId },
        })
        assert.throws(
            () => client.applyPatch('regular', decode('SyncdPatch', patch)),
            /patch MAC of regular does not match/,
        )
    })

    it('builds a patch the other side can read', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        store.setCollectionState('regular', {
            initialized: true,
            version: 4,
            hash: APP_STATE_EMPTY_LT_HASH,
            indexValueMap: new Map(),
        })

        const built = client.buildOutgoingPatch(
            'regular',
            store.getCollectionState('regular'),
            [
                {
                    collection: 'regular',
                    operation: 'set',
                    index: 'the-index',
                    value: { pushNameSetting: { name: 'Lava' } },
                    version: 1,
                },
            ],
            key,
        )
        assert.equal(built.version, 5)

        // The other side reads the patch with the same key. The patch itself
        // carries no version: the server assigns it, because it knows which
        // version the client was at.
        const crypto = new AppStateCrypto()
        const decoded = decode('SyncdPatch', built.patch)
        const mutations = decoded.mutations as {
            operation?: number
            record?: { index?: { blob?: Uint8Array }; value?: { blob?: Uint8Array } }
        }[]
        assert.equal(mutations.length, 1)
        assert.equal(mutations[0]!.operation, 0)

        const decrypted = crypto.decryptMutation({
            operation: 'set',
            keyId: key.keyId,
            keyData: key.keyData,
            indexMac: mutations[0]!.record!.index!.blob!,
            valueBlob: mutations[0]!.record!.value!.blob!,
        })
        assert.equal(decrypted.index, 'the-index')
        assert.deepEqual(decrypted.value, { pushNameSetting: { name: 'Lava' } })

        // The MACs of the patch cover the state the patch produces.
        const valueMacs = [decrypted.valueMac]
        const expectedSnapshotMac = crypto.generateSnapshotMac(key.keyData, built.hash, 5, 'regular')
        assert.equal(toHex(decoded.snapshotMac as Uint8Array), toHex(expectedSnapshotMac))
        assert.equal(
            toHex(decoded.patchMac as Uint8Array),
            toHex(crypto.generatePatchMac(key.keyData, expectedSnapshotMac, valueMacs, 5, 'regular')),
        )
    })

    it('pushes the pending changes into the request', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        store.setCollectionState('regular', {
            initialized: true,
            version: 4,
            hash: APP_STATE_EMPTY_LT_HASH,
            indexValueMap: new Map(),
        })

        const node = client.buildCollectionRequest(
            'regular',
            [
                {
                    collection: 'regular',
                    operation: 'set',
                    index: 'the-index',
                    value: { pushNameSetting: { name: 'Lava' } },
                    version: 1,
                },
            ],
            key,
        )
        const children = node.content as BinaryNode[]
        assert.equal(children.length, 1)
        assert.equal(children[0]!.tag, 'patch')
        assert.ok(children[0]!.content instanceof Uint8Array)
    })

    it('runs a round and reports the state of every collection', async () => {
        const { client } = makeClient({
            answer: (node) => {
                const collections = (node.content as BinaryNode[])[0]!.content as BinaryNode[]
                return {
                    tag: 'iq',
                    attrs: { id: node.attrs.id ?? '', type: 'result' },
                    content: [
                        {
                            tag: 'sync',
                            attrs: {},
                            content: collections.map((collection) =>
                                collectionNode({
                                    name: collection.attrs.name ?? '',
                                    version: '1',
                                    type: 'success',
                                }),
                            ),
                        },
                    ],
                }
            },
        })
        const result = await client.sync({ collections: ['regular', 'regular_low'] })
        assert.equal(result.collections.length, 2)
        assert.equal(result.collections[0]!.collection, 'regular')
        assert.equal(result.collections[0]!.state, APP_STATE_COLLECTION_STATES.SUCCESS)
    })

    it('reports a collection the server left out as retryable', async () => {
        const { client } = makeClient({
            answer: (node) => ({
                tag: 'iq',
                attrs: { id: node.attrs.id ?? '', type: 'result' },
                content: [
                    {
                        tag: 'sync',
                        attrs: {},
                        content: [
                            collectionNode({ name: 'regular', version: '1', type: 'success' }),
                        ],
                    },
                ],
            }),
        })
        const result = await client.sync({ collections: ['regular', 'regular_low'] })
        const missing = result.collections.find((entry) => entry.collection === 'regular_low')
        assert.equal(missing?.state, APP_STATE_COLLECTION_STATES.ERROR_RETRY)
    })

    it('keeps only the last change of a record', async () => {
        let seen: BinaryNode | undefined
        const { client } = makeClient({
            answer: (node) => {
                seen = node
                return {
                    tag: 'iq',
                    attrs: { id: node.attrs.id ?? '', type: 'result' },
                    content: [
                        {
                            tag: 'sync',
                            attrs: {},
                            content: [
                                collectionNode({ name: 'regular', version: '1', type: 'success' }),
                            ],
                        },
                    ],
                }
            },
        })
        await client.sync({
            collections: ['regular'],
            pendingMutations: [
                { collection: 'regular', operation: 'set', index: 'a', value: {}, version: 1 },
                { collection: 'regular', operation: 'set', index: 'a', value: {}, version: 2 },
            ],
        })
        assert.ok(seen)
        const collection = (seen.content as BinaryNode[])[0]!.content as BinaryNode[]
        const patchNode = (collection[0]!.content as BinaryNode[])[0]!
        const patch = patchNode.content as Uint8Array
        const decoded = decode('SyncdPatch', patch)
        const mutations = decoded.mutations as unknown[]
        assert.equal(mutations.length, 1)
    })

    it('reports a conflict while the client has changes to push', async () => {
        const { client } = makeClient({
            answer: (node) => ({
                tag: 'iq',
                attrs: { id: node.attrs.id ?? '', type: 'result' },
                content: [
                    {
                        tag: 'sync',
                        attrs: {},
                        content: [
                            {
                                tag: 'collection',
                                attrs: { name: 'regular', version: '7', type: 'error' },
                                content: [{ tag: 'error', attrs: { code: '409' } }],
                            },
                        ],
                    },
                ],
            }),
        })
        const result = await client.sync({
            collections: ['regular'],
            pendingMutations: [
                { collection: 'regular', operation: 'set', index: 'a', value: {}, version: 1 },
            ],
        })
        assert.equal(result.collections[0]!.state, APP_STATE_COLLECTION_STATES.CONFLICT)
        // The changes were not uploaded, so they stay pending.
        assert.equal(result.collections[0]!.uploaded, false)
    })

    it('reports a conflict as a success when the client has nothing to push', async () => {
        const { client } = makeClient({
            answer: (node) => ({
                tag: 'iq',
                attrs: { id: node.attrs.id ?? '', type: 'result' },
                content: [
                    {
                        tag: 'sync',
                        attrs: {},
                        content: [
                            {
                                tag: 'collection',
                                attrs: { name: 'regular', version: '7', type: 'error' },
                                content: [{ tag: 'error', attrs: { code: '409' } }],
                            },
                        ],
                    },
                ],
            }),
        })
        const result = await client.sync({ collections: ['regular'] })
        assert.equal(result.collections[0]!.state, APP_STATE_COLLECTION_STATES.SUCCESS)
        assert.equal(result.collections[0]!.uploaded, true)
    })

    it('does not push the same changes twice after a conflict', async () => {
        let rounds = 0
        const { client } = makeClient({
            answer: (node) => {
                rounds += 1
                const collections = (node.content as BinaryNode[])[0]!.content as BinaryNode[]
                if (rounds === 1) {
                    return {
                        tag: 'iq',
                        attrs: { id: node.attrs.id ?? '', type: 'result' },
                        content: [
                            {
                                tag: 'sync',
                                attrs: {},
                                content: [
                                    {
                                        tag: 'collection',
                                        attrs: { name: 'regular', version: '7', type: 'error' },
                                        content: [{ tag: 'error', attrs: { code: '409' } }],
                                    },
                                ],
                            },
                        ],
                    }
                }
                // The second round only asks for the state.
                assert.equal(collections[0]!.content, undefined)
                return {
                    tag: 'iq',
                    attrs: { id: node.attrs.id ?? '', type: 'result' },
                    content: [
                        {
                            tag: 'sync',
                            attrs: {},
                            content: [
                                collectionNode({ name: 'regular', version: '7', type: 'success' }),
                            ],
                        },
                    ],
                }
            },
        })
        const result = await client.sync({
            collections: ['regular'],
            pendingMutations: [
                { collection: 'regular', operation: 'set', index: 'a', value: {}, version: 1 },
            ],
        })
        assert.equal(rounds, 2)
        assert.equal(result.collections[0]!.uploaded, false)
    })

    it('applies the patches in the order of their versions', async () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        const crypto = new AppStateCrypto()

        /** Builds a patch that sets one record. */
        const buildPatch = (index: string, version: number): Uint8Array => {
            const encrypted = crypto.encryptMutation({
                operation: 'set',
                keyId: key.keyId,
                keyData: key.keyData,
                index,
                value: { pushNameSetting: { name: index } },
                version: 1,
            })
            const hash = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [encrypted.valueMac])
            const snapshotMac = crypto.generateSnapshotMac(key.keyData, hash, version, 'regular')
            const patchMac = crypto.generatePatchMac(
                key.keyData,
                snapshotMac,
                [encrypted.valueMac],
                version,
                'regular',
            )
            return encode('SyncdPatch', {
                version: { version },
                mutations: [
                    {
                        operation: 0,
                        record: {
                            index: { blob: encrypted.indexMac },
                            value: { blob: encrypted.valueBlob },
                            keyId: { id: key.keyId },
                        },
                    },
                ],
                snapshotMac,
                patchMac,
                keyId: { id: key.keyId },
            })
        }

        const { client: roundClient } = makeClient({
            store,
            answer: (node) => {
                const collections = (node.content as BinaryNode[])[0]!.content as BinaryNode[]
                return {
                    tag: 'iq',
                    attrs: { id: node.attrs.id ?? '', type: 'result' },
                    content: [
                        {
                            tag: 'sync',
                            attrs: {},
                            content: [
                                {
                                    tag: 'collection',
                                    attrs: { name: 'regular', version: '2', type: 'success' },
                                    content: [
                                        {
                                            tag: 'patches',
                                            attrs: {},
                                            // The server sends the patches
                                            // in the wrong order on purpose.
                                            content: [
                                                { tag: 'patch', attrs: {}, content: buildPatch('second', 2) },
                                                { tag: 'patch', attrs: {}, content: buildPatch('first', 1) },
                                            ],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                }
            },
        })
        const result = await roundClient.sync({ collections: ['regular'] })
        assert.equal(result.collections[0]!.state, APP_STATE_COLLECTION_STATES.SUCCESS)
        assert.equal(result.collections[0]!.mutations.length, 2)
        assert.equal(result.collections[0]!.mutations[0]!.index, 'first')
        assert.equal(result.collections[0]!.mutations[1]!.index, 'second')
        assert.equal(roundClient.store.getCollectionState('regular').version, 2)
    })

    it('downloads the mutations of a patch the server kept on the CDN', async () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: key.keyId,
            keyData: key.keyData,
            index: 'the-index',
            value: { pushNameSetting: { name: 'Lava' } },
            version: 1,
        })
        const hash = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [encrypted.valueMac])
        const snapshotMac = crypto.generateSnapshotMac(key.keyData, hash, 1, 'regular')
        const patchMac = crypto.generatePatchMac(
            key.keyData,
            snapshotMac,
            [encrypted.valueMac],
            1,
            'regular',
        )
        // The mutations themselves live on the CDN.
        const external = encode('SyncdMutations', {
            mutations: [
                {
                    operation: 0,
                    record: {
                        index: { blob: encrypted.indexMac },
                        value: { blob: encrypted.valueBlob },
                        keyId: { id: key.keyId },
                    },
                },
            ],
        })
        const patch = encode('SyncdPatch', {
            version: { version: 1 },
            snapshotMac,
            patchMac,
            keyId: { id: key.keyId },
            externalMutations: {
                mediaKey: new Uint8Array(32).fill(3),
                directPath: '/v/t62.7118-24/whatever',
                fileSha256: new Uint8Array(32).fill(4),
                fileEncSha256: new Uint8Array(32).fill(5),
            },
        })

        const seen: Array<{ collection: string; kind: string; directPath: string }> = []
        const { client: roundClient } = makeClient({
            store,
            downloadExternalBlob: async (collection, kind, reference) => {
                seen.push({
                    collection,
                    kind,
                    directPath: (reference as { directPath: string }).directPath,
                })
                return external
            },
            answer: (node) => ({
                tag: 'iq',
                attrs: { id: node.attrs.id ?? '', type: 'result' },
                content: [
                    {
                        tag: 'sync',
                        attrs: {},
                        content: [
                            {
                                tag: 'collection',
                                attrs: { name: 'regular', version: '1', type: 'success' },
                                content: [
                                    {
                                        tag: 'patches',
                                        attrs: {},
                                        content: [{ tag: 'patch', attrs: {}, content: patch }],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            }),
        })
        const result = await roundClient.sync({ collections: ['regular'] })
        assert.equal(seen.length, 1)
        assert.equal(seen[0]!.collection, 'regular')
        assert.equal(seen[0]!.kind, 'patch')
        assert.equal(seen[0]!.directPath, '/v/t62.7118-24/whatever')
        assert.equal(result.collections[0]!.mutations.length, 1)
        assert.equal(result.collections[0]!.mutations[0]!.index, 'the-index')
        assert.equal(roundClient.store.getCollectionState('regular').version, 1)
    })

    it('refuses a patch with a terminal exit code', () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        const patch = encode('SyncdPatch', {
            version: { version: 1 },
            mutations: [],
            snapshotMac: new Uint8Array(32),
            patchMac: new Uint8Array(32),
            keyId: { id: key.keyId },
            exitCode: { code: 405, text: 'the collection is not allowed' },
        })
        assert.throws(
            () => client.applyPatch('regular', decode('SyncdPatch', patch)),
            /terminal exit code 405/,
        )
    })

    it('advances the version when the server accepts the patch', async () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        store.setCollectionState('regular', {
            initialized: true,
            version: 4,
            hash: APP_STATE_EMPTY_LT_HASH,
            indexValueMap: new Map(),
        })

        const { client: roundClient } = makeClient({
            store,
            answer: (node) => ({
                tag: 'iq',
                attrs: { id: node.attrs.id ?? '', type: 'result' },
                content: [
                    {
                        tag: 'sync',
                        attrs: {},
                        content: [
                            collectionNode({ name: 'regular', version: '5', type: 'success' }),
                        ],
                    },
                ],
            }),
        })
        const result = await roundClient.sync({
            collections: ['regular'],
            pendingMutations: [
                { collection: 'regular', operation: 'set', index: 'a', value: {}, version: 1 },
            ],
        })
        assert.equal(result.collections[0]!.uploaded, true)
        assert.equal(store.getCollectionState('regular').version, 5)
        assert.equal(store.getCollectionState('regular').initialized, true)
    })

    it('asks the other devices for a key it does not have', async () => {
        const { client, store } = makeClient()
        const key = generateSyncKey(1, 1000)
        store.upsertKeys([key])
        // A patch that was encrypted for another key.
        const otherKey = generateSyncKey(2, 2000)
        const crypto = new AppStateCrypto()
        const encrypted = crypto.encryptMutation({
            operation: 'set',
            keyId: otherKey.keyId,
            keyData: otherKey.keyData,
            index: 'the-index',
            value: { pushNameSetting: { name: 'Lava' } },
            version: 1,
        })
        const hash = crypto.ltHashAdd(APP_STATE_EMPTY_LT_HASH, [encrypted.valueMac])
        const snapshotMac = crypto.generateSnapshotMac(otherKey.keyData, hash, 1, 'regular')
        const patchMac = crypto.generatePatchMac(
            otherKey.keyData,
            snapshotMac,
            [encrypted.valueMac],
            1,
            'regular',
        )
        const patch = encode('SyncdPatch', {
            version: { version: 1 },
            mutations: [
                {
                    operation: 0,
                    record: {
                        index: { blob: encrypted.indexMac },
                        value: { blob: encrypted.valueBlob },
                        keyId: { id: otherKey.keyId },
                    },
                },
            ],
            snapshotMac,
            patchMac,
            keyId: { id: otherKey.keyId },
        })

        const asked: string[][] = []
        const { client: roundClient } = makeClient({
            store,
            onMissingKeys: (keyIds) => {
                asked.push(keyIds.map((entry) => toHex(entry)))
            },
            answer: (node) => ({
                tag: 'iq',
                attrs: { id: node.attrs.id ?? '', type: 'result' },
                content: [
                    {
                        tag: 'sync',
                        attrs: {},
                        content: [
                            {
                                tag: 'collection',
                                attrs: { name: 'regular', version: '1', type: 'success' },
                                content: [
                                    {
                                        tag: 'patches',
                                        attrs: {},
                                        content: [{ tag: 'patch', attrs: {}, content: patch }],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            }),
        })
        const result = await roundClient.sync({ collections: ['regular'] })
        assert.equal(result.collections[0]!.state, APP_STATE_COLLECTION_STATES.BLOCKED)
        assert.equal(result.missingKeyIds.length, 1)
        assert.equal(toHex(result.missingKeyIds[0]!), toHex(otherKey.keyId))
        assert.equal(asked.length, 1)
        assert.deepEqual(asked[0], [toHex(otherKey.keyId)])
    })
})
