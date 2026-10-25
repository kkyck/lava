/**
 * The app-state synchronisation client.
 *
 * The server brokers the app state of an account: the chat list, the
 * contacts, the labels, the mute and archive settings. A client asks for a
 * *collection* it cares about and the server answers with the state the
 * account currently has.
 *
 * The exchange looks like this:
 *
 * ```xml
 *   <iq to="s.whatsapp.net" type="set" xmlns="w:sync:app:state">
 *     <sync data_namespace="3">
 *       <collection name="regular" version="12" return_snapshot="false" />
 *     </sync>
 *   </iq>
 * ```
 *
 * The answer carries either a snapshot (the whole collection) or a list of
 * patches (the changes since the version the client has). Both are encrypted
 * per sync key and MACed, so the client can tell whether the state really
 * belongs to the account.
 *
 * The mobile primary device is the one that owns the account state, so it
 * asks for a snapshot instead of uploading its own changes.
 */

import { equalBytes, toHex } from '../crypto/primitives.js'
import { decode, encode } from '../proto/codec.js'
import { WA_IQ_TYPES, WA_NODE_TAGS, WA_XMLNS } from '../protocol/constants.js'
import {
    decodeNodeContentBytes,
    findNodeChild,
    findNodeChildrenByTags,
    getNodeChildrenByTag,
} from '../transport/node/helpers.js'
import type { BinaryNode } from '../transport/binary/types.js'
import {
    APP_STATE_COLLECTION_STATES,
    APP_STATE_COLLECTIONS,
    APP_STATE_DEFAULT_COLLECTIONS,
    APP_STATE_DEFAULT_COLLECTION_VERSION,
    APP_STATE_ERROR_CODES,
    APP_STATE_EMPTY_LT_HASH,
} from './constants.js'
import { AppStateCrypto, type AppStateOperation } from './crypto.js'
import { generateSyncKey, type AppStateSyncKey } from './keys.js'
import { AppStateStore, type AppStateCollectionState } from './store.js'

/** A change the client wants to push into a collection. */
export interface AppStatePendingMutation {
    /** The collection the change belongs to. */
    collection: string
    /** Whether the record is set or removed. */
    operation: AppStateOperation
    /** The index of the record, as text. */
    index: string
    /** The value of the record; absent for a removal. */
    value?: Record<string, unknown>
    /** The version of the record. */
    version: number
}

/** A change that was read from the server. */
export interface AppStateAppliedMutation {
    /** The collection the change belongs to. */
    collection: string
    /** Whether the record was set or removed. */
    operation: AppStateOperation
    /** Where the change came from. */
    source: 'snapshot' | 'patch'
    /** The index of the record, as text. */
    index: string
    /** The value of the record; absent for a removal. */
    value?: Record<string, unknown>
    /** The version of the record. */
    version: number
    /** The MAC over the index of the record. */
    indexMac: Uint8Array
    /** The MAC over the encrypted value of the record. */
    valueMac: Uint8Array
    /** The id of the sync key the record was encrypted for. */
    keyId: Uint8Array
}

/** The outcome of one collection. */
export interface AppStateCollectionResult {
    /** The collection. */
    collection: string
    /** The state the server reported. */
    state: string
    /** The version the collection ended at. */
    version?: number
    /** The changes that were applied. */
    mutations: AppStateAppliedMutation[]
    /**
     * Whether the client uploaded its own changes to the collection.
     *
     * A change that was not uploaded stays pending.
     */
    uploaded: boolean
}

/** The outcome of a sync round. */
export interface AppStateSyncResult {
    /** The result of every requested collection. */
    collections: AppStateCollectionResult[]
    /**
     * The sync keys the server needed but the device does not have.
     *
     * The client asks the other devices of the account for them.
     */
    missingKeyIds: Uint8Array[]
}

/** The options of a sync round. */
export interface AppStateSyncOptions {
    /** The collections to sync; the default is every known collection. */
    collections?: readonly string[]
    /** The changes to push into the collections. */
    pendingMutations?: readonly AppStatePendingMutation[]
    /** The timeout of the IQ round trip. */
    timeoutMs?: number
}

/** A reference to a blob on the CDN. */
export interface AppStateExternalBlob {
    /** The key the blob was encrypted with. */
    mediaKey: Uint8Array
    /** The path the CDN serves the blob under. */
    directPath: string
    /** The SHA-256 of the plaintext. */
    fileSha256?: Uint8Array
    /** The SHA-256 of the encrypted bytes. */
    fileEncSha256?: Uint8Array
}

/** The options of the app-state sync client. */
export interface AppStateSyncClientOptions {
    /** Sends an IQ and waits for the answer. */
    query: (node: BinaryNode, timeoutMs?: number) => Promise<BinaryNode>
    /** The store that holds the keys and the collection state. */
    store: AppStateStore
    /** Returns the JID of the paired account. */
    getMeJid?: () => string | undefined
    /** The server that handles the request. */
    hostDomain?: string
    /**
     * Whether this device is the primary device of a mobile session.
     *
     * The primary device owns the account state, so it asks the server for a
     * snapshot instead of uploading its own changes.
     */
    mobilePrimary?: boolean
    /** Downloads and decrypts a blob the server referenced. */
    downloadExternalBlob?: (
        collection: string,
        kind: 'snapshot' | 'patch',
        reference: AppStateExternalBlob,
    ) => Promise<Uint8Array>
    /**
     * Called when the server needs a sync key the device does not have.
     *
     * The client asks the other devices of the account for the key.
     */
    onMissingKeys?: (keyIds: readonly Uint8Array[]) => void | Promise<void>
    /** The crypto; a fresh one is created when omitted. */
    crypto?: AppStateCrypto
    /** The logger the recoverable problems are reported to. */
    logger?: {
        log: (record: {
            level: 'warn' | 'debug'
            message: string
            fields?: Record<string, unknown>
        }) => void
    }
}

/**
 * Raised when a collection cannot be processed because a sync key is
 * missing.
 *
 * The client asks the peer for the key and tries again.
 */
export class AppStateMissingKeyError extends Error {
    /** The id of the key that is missing. */
    readonly keyId: Uint8Array | null
    /** The collection that was blocked. */
    readonly collection: string

    /**
     * @param message The message.
     * @param keyId The id of the missing key.
     * @param collection The blocked collection.
     */
    constructor(message: string, keyId: Uint8Array | null, collection: string) {
        super(message)
        this.name = 'AppStateMissingKeyError'
        this.keyId = keyId
        this.collection = collection
    }
}

/** The maximum number of rounds a single sync may take. */
const APP_STATE_MAX_ROUNDS = 5

/**
 * The app-state synchronisation client.
 *
 * The client owns the key inventory, applies the snapshots and patches the
 * server sends and encrypts the changes the client wants to push.
 */
export class AppStateSyncClient {
    private readonly options: AppStateSyncClientOptions
    private readonly crypto: AppStateCrypto
    private inFlight: Promise<AppStateSyncResult> | null = null

    /**
     * @param options The options.
     */
    constructor(options: AppStateSyncClientOptions) {
        this.options = options
        this.crypto = options.crypto ?? new AppStateCrypto()
    }

    /** The store that holds the keys and the collection state. */
    get store(): AppStateStore {
        return this.options.store
    }

    /**
     * Returns the key the device writes with, generating one when the store
     * is still empty.
     */
    ensureSyncKey(): AppStateSyncKey {
        const existing = this.store.getActiveSyncKey()
        if (existing) return existing
        const key = generateSyncKey(this.deviceIndex() ?? 0, Date.now())
        this.store.upsertKeys([key])
        this.crypto.clearCache()
        return key
    }

    /**
     * Imports the keys of a peer.
     *
     * @param keys The keys to import.
     * @returns The number of keys that were new.
     */
    importKeys(keys: readonly AppStateSyncKey[]): number {
        const added = this.store.upsertKeys(keys)
        if (added > 0) this.crypto.clearCache()
        return added
    }

    /**
     * Runs one sync round.
     *
     * Concurrent calls share the same round.
     *
     * @param options The options.
     */
    async sync(options: AppStateSyncOptions = {}): Promise<AppStateSyncResult> {
        if (this.inFlight) return this.inFlight
        const round = this.syncOnce(options)
        this.inFlight = round
        try {
            return await round
        } finally {
            if (this.inFlight === round) this.inFlight = null
        }
    }

    /**
     * Builds the IQ that asks the server for the state of the collections.
     *
     * @param collectionNodes The `<collection/>` children.
     */
    buildSyncIqNode(collectionNodes: BinaryNode[]): BinaryNode {
        return {
            tag: WA_NODE_TAGS.IQ,
            attrs: {
                to: this.options.hostDomain ?? 's.whatsapp.net',
                type: WA_IQ_TYPES.SET,
                xmlns: WA_XMLNS.APP_STATE_SYNC,
            },
            content: [
                {
                    tag: WA_NODE_TAGS.SYNC,
                    attrs: this.isMobilePrimary() ? { data_namespace: '3' } : {},
                    content: collectionNodes,
                },
            ],
        }
    }

    /**
     * Builds the `<collection/>` child of a sync IQ.
     *
     * @param collection The collection name.
     * @param pending The changes that should be pushed into it.
     * @param activeKey The key the changes are encrypted for.
     */
    buildCollectionRequest(
        collection: string,
        pending: readonly AppStatePendingMutation[],
        activeKey: AppStateSyncKey | null,
    ): BinaryNode {
        return this.buildCollectionRequestDetailed(collection, pending, activeKey).node
    }

    /**
     * Builds the `<collection/>` child of a sync IQ and reports what the
     * client uploaded.
     *
     * The upload is skipped when the device has no state of the collection
     * yet: the server would reject a patch that is based on a version the
     * device never saw. The collection is fetched again in the next round,
     * with the snapshot the server sends.
     *
     * @param collection The collection name.
     * @param pending The changes that should be pushed into it.
     * @param activeKey The key the changes are encrypted for.
     */
    buildCollectionRequestDetailed(
        collection: string,
        pending: readonly AppStatePendingMutation[],
        activeKey: AppStateSyncKey | null,
    ): {
        node: BinaryNode
        /** The patch that was uploaded, when one was. */
        outgoing?: { version: number; hash: Uint8Array; indexValueMap: Map<string, Uint8Array> }
        /** Whether the upload was skipped because the state is missing. */
        skippedUpload: boolean
    } {
        const state = this.store.getCollectionState(collection)
        const hasState = state.initialized
        // The primary device owns the account state, so it asks for a
        // snapshot instead of pushing its own changes.
        const requestSnapshot = !this.isMobilePrimary() && !hasState
        const attrs: Record<string, string> = {
            name: collection,
            version: String(hasState ? state.version : APP_STATE_DEFAULT_COLLECTION_VERSION),
            return_snapshot: requestSnapshot ? 'true' : 'false',
        }
        const children: BinaryNode[] = []
        let outgoing:
            | { version: number; hash: Uint8Array; indexValueMap: Map<string, Uint8Array> }
            | undefined
        let skippedUpload = false
        if (pending.length > 0) {
            if (!hasState && !this.isMobilePrimary()) {
                // The client does not know the version the server is at, so
                // it cannot upload a patch yet.
                skippedUpload = true
            } else {
                const patch = this.buildOutgoingPatch(collection, state, pending, activeKey)
                outgoing = {
                    version: patch.version,
                    hash: patch.hash,
                    indexValueMap: patch.indexValueMap,
                }
                children.push({
                    tag: WA_NODE_TAGS.PATCH,
                    attrs: {},
                    content: patch.patch,
                })
            }
        }
        return {
            node: {
                tag: WA_NODE_TAGS.COLLECTION,
                attrs,
                content: children.length > 0 ? children : undefined,
            },
            ...(outgoing ? { outgoing } : {}),
            skippedUpload,
        }
    }

    /**
     * Parses the answer of the server.
     *
     * @param iqNode The IQ the server answered with.
     */
    parseSyncResponse(iqNode: BinaryNode): AppStateCollectionPayload[] {
        if (iqNode.tag !== WA_NODE_TAGS.IQ) {
            throw new Error(`app-state: invalid sync response tag ${iqNode.tag}`)
        }
        const syncNode = findNodeChild(iqNode, WA_NODE_TAGS.SYNC)
        if (!syncNode) {
            if (iqNode.attrs.type === WA_IQ_TYPES.ERROR) {
                const errorNode = findNodeChild(iqNode, WA_NODE_TAGS.ERROR)
                const code = errorNode?.attrs.code ?? 'unknown'
                const text = errorNode?.attrs.text ?? 'unknown'
                throw new Error(`app-state: sync iq failed (${code}: ${text})`)
            }
            throw new Error('app-state: the sync response has no <sync> node')
        }
        const payloads: AppStateCollectionPayload[] = []
        for (const collectionNode of getNodeChildrenByTag(syncNode, WA_NODE_TAGS.COLLECTION)) {
            const name = collectionNode.attrs.name
            if (!name || !isKnownCollection(name)) {
                throw new Error(`app-state: invalid collection name ${name ?? ''}`)
            }
            const versionAttr = collectionNode.attrs.version
            let version: number | undefined
            if (versionAttr !== undefined) {
                const parsed = Number.parseInt(versionAttr, 10)
                if (!Number.isSafeInteger(parsed) || parsed < 0) {
                    throw new Error(`app-state: invalid collection version ${versionAttr}`)
                }
                version = parsed
            }
            const [patchesNode, snapshotNode] = findNodeChildrenByTags(collectionNode, [
                WA_NODE_TAGS.PATCHES,
                WA_NODE_TAGS.SNAPSHOT,
            ])
            const patches: AppStatePatch[] = []
            if (patchesNode) {
                for (const patchNode of getNodeChildrenByTag(patchesNode, WA_NODE_TAGS.PATCH)) {
                    const bytes = decodeNodeContentBytes(
                        patchNode.content,
                        'collection.patches.patch',
                    )
                    const patch = decode('SyncdPatch', bytes) as unknown as AppStatePatch
                    const reference = patch.externalMutations
                    if (reference) {
                        patch.externalMutations = {
                            mediaKey: asBytes(reference.mediaKey),
                            directPath:
                                typeof reference.directPath === 'string'
                                    ? reference.directPath
                                    : '',
                            fileSha256: asOptionalBytes(reference.fileSha256),
                            fileEncSha256: asOptionalBytes(reference.fileEncSha256),
                        }
                    }
                    patches.push(patch)
                }
            }
            let snapshotReference: AppStateExternalBlob | undefined
            if (snapshotNode) {
                const bytes = decodeNodeContentBytes(
                    snapshotNode.content,
                    'collection.snapshot',
                )
                const reference = decode('ExternalBlobReference', bytes) as Record<string, unknown>
                snapshotReference = {
                    mediaKey: asBytes(reference.mediaKey),
                    directPath: typeof reference.directPath === 'string' ? reference.directPath : '',
                    fileSha256: asOptionalBytes(reference.fileSha256),
                    fileEncSha256: asOptionalBytes(reference.fileEncSha256),
                }
            }
            payloads.push({
                collection: name,
                state: parseCollectionState(collectionNode),
                version,
                patches,
                snapshotReference,
            })
        }
        return payloads
    }

    /**
     * Applies a snapshot to a collection.
     *
     * @param collection The collection.
     * @param snapshot The snapshot.
     * @returns The changes the snapshot carried.
     */
    applySnapshot(collection: string, snapshot: AppStateSnapshot): AppStateAppliedMutation[] {
        const version = readVersion(snapshot.version, `snapshot.version (${collection})`)
        const snapshotKeyId = readKeyId(snapshot.keyId)
        const snapshotKey = snapshotKeyId ? this.store.getKey(snapshotKeyId) : undefined
        if (snapshotKeyId && !snapshotKey) {
            throw new AppStateMissingKeyError(
                `app-state: missing snapshot key ${toHex(snapshotKeyId)} for ${collection}`,
                snapshotKeyId,
                collection,
            )
        }

        const indexValueMap = new Map<string, Uint8Array>()
        const mutations: AppStateAppliedMutation[] = []
        for (const record of snapshot.records ?? []) {
            const keyId = readKeyId(record.keyId)
            const key = keyId ? this.store.getKey(keyId) : undefined
            if (!key) {
                throw new AppStateMissingKeyError(
                    `app-state: missing record key ${keyId ? toHex(keyId) : 'unknown'} for ${collection}`,
                    keyId,
                    collection,
                )
            }
            const indexMac = readBlob(record.index, 'snapshot.record.index')
            const valueBlob = readBlob(record.value, 'snapshot.record.value')
            const decrypted = this.crypto.decryptMutation({
                operation: 'set',
                keyId: key.keyId,
                keyData: key.keyData,
                indexMac,
                valueBlob,
            })
            indexValueMap.set(toHex(decrypted.indexMac), decrypted.valueMac)
            mutations.push({
                collection,
                operation: 'set',
                source: 'snapshot',
                index: decrypted.index,
                ...(decrypted.value !== undefined ? { value: decrypted.value } : {}),
                version: decrypted.version,
                indexMac: decrypted.indexMac,
                valueMac: decrypted.valueMac,
                keyId: key.keyId,
            })
        }

        const ltHash = this.crypto.ltHashAdd(
            APP_STATE_EMPTY_LT_HASH,
            [...indexValueMap.values()],
        )
        if (snapshotKey) {
            const expected = this.crypto.generateSnapshotMac(
                snapshotKey.keyData,
                ltHash,
                version,
                collection,
            )
            if (!equalBytes(expected, snapshot.mac ?? new Uint8Array(0))) {
                // A snapshot whose MAC does not match cannot be trusted, but
                // throwing would make the client ask for it forever. The
                // partial state is kept instead.
                this.warn(
                    `app-state: the snapshot MAC of ${collection} does not match; keeping the partial state`,
                )
            }
        }
        this.store.setCollectionState(collection, {
            initialized: true,
            version,
            hash: ltHash,
            indexValueMap,
        })
        return mutations
    }

    /**
     * Applies a patch to a collection.
     *
     * @param collection The collection.
     * @param patch The patch.
     * @returns The changes the patch carried.
     */
    applyPatch(collection: string, patch: AppStatePatch): AppStateAppliedMutation[] {
        const patchVersion = readVersion(patch.version, `patch.version (${collection})`)
        const exitCode = patch.exitCode?.code
        if (exitCode !== undefined && exitCode !== null && Number(exitCode) !== 0) {
            throw new Error(
                `app-state: the patch of ${collection} has a terminal exit code ${String(exitCode)}: ${
                    patch.exitCode?.text ?? ''
                }`,
            )
        }
        const current = this.store.getCollectionState(collection)
        if (patchVersion <= current.version) {
            /**
             * The patch is not newer than the local state: it was already
             * applied, or the server sent an older one. Applying it again
             * would move the collection backwards, so it is skipped. The
             * server repeats the patches of the last rounds on every
             * connect, so this is the normal case, not an error.
             */
            this.log(`app-state: skipped the outdated patch of ${collection} (${patchVersion})`)
            return []
        }
        if (current.version !== patchVersion - 1) {
            throw new Error(
                `app-state: patch version mismatch for ${collection}: local=${current.version}, incoming=${patchVersion}`,
            )
        }
        const patchKeyId = readKeyId(patch.keyId)
        const patchKey = patchKeyId ? this.store.getKey(patchKeyId) : undefined
        if (patchKeyId && !patchKey) {
            throw new AppStateMissingKeyError(
                `app-state: missing patch key ${toHex(patchKeyId)} for ${collection}`,
                patchKeyId,
                collection,
            )
        }

        const mutations: AppStateAppliedMutation[] = []
        const valueMacs: Uint8Array[] = []
        for (const mutation of patch.mutations ?? []) {
            const operation = mutation.operation === 1 ? 'remove' : 'set'
            const record = mutation.record
            if (!record) {
                throw new Error(`app-state: a patch mutation of ${collection} has no record`)
            }
            const keyId = readKeyId(record.keyId)
            const key = keyId ? this.store.getKey(keyId) : undefined
            if (!key) {
                throw new AppStateMissingKeyError(
                    `app-state: missing mutation key ${keyId ? toHex(keyId) : 'unknown'} for ${collection}`,
                    keyId,
                    collection,
                )
            }
            const indexMac = readBlob(record.index, 'patch.record.index')
            const valueBlob = readBlob(record.value, 'patch.record.value')
            const decrypted = this.crypto.decryptMutation({
                operation,
                keyId: key.keyId,
                keyData: key.keyData,
                indexMac,
                valueBlob,
            })
            valueMacs.push(decrypted.valueMac)
            mutations.push({
                collection,
                operation,
                source: 'patch',
                index: decrypted.index,
                ...(decrypted.value !== undefined ? { value: decrypted.value } : {}),
                version: decrypted.version,
                indexMac: decrypted.indexMac,
                valueMac: decrypted.valueMac,
                keyId: key.keyId,
            })
        }

        const next = this.computeNextCollectionState(current, mutations)
        if (patchKey) {
            this.assertPatchMacs(collection, patch, patchKey.keyData, patchVersion, next.hash, valueMacs)
        }
        this.store.setCollectionState(collection, {
            initialized: true,
            version: patchVersion,
            hash: next.hash,
            indexValueMap: next.indexValueMap,
        })
        return mutations
    }

    /**
     * Encrypts the changes the client wants to push into a collection.
     *
     * @param collection The collection.
     * @param state The current state of the collection.
     * @param pending The changes.
     * @param activeKey The key the changes are encrypted for.
     */
    buildOutgoingPatch(
        collection: string,
        state: AppStateCollectionState,
        pending: readonly AppStatePendingMutation[],
        activeKey: AppStateSyncKey | null,
    ): {
        patch: Uint8Array
        version: number
        hash: Uint8Array
        indexValueMap: Map<string, Uint8Array>
    } {
        if (!activeKey) {
            throw new AppStateMissingKeyError(
                `app-state: no sync key available to upload ${collection}`,
                null,
                collection,
            )
        }
        const mutations = pending.map((mutation) => {
            const encrypted = this.crypto.encryptMutation({
                operation: mutation.operation,
                keyId: activeKey.keyId,
                keyData: activeKey.keyData,
                index: mutation.index,
                ...(mutation.operation === 'set' && mutation.value !== undefined
                    ? { value: mutation.value }
                    : {}),
                version: mutation.version,
            })
            return { mutation, encrypted }
        })

        const next = this.computeNextCollectionState(state, mutations.map((entry) => ({
            collection,
            operation: entry.mutation.operation,
            source: 'patch',
            index: entry.mutation.index,
            version: entry.mutation.version,
            indexMac: entry.encrypted.indexMac,
            valueMac: entry.encrypted.valueMac,
            keyId: activeKey.keyId,
        })))

        const patchVersion = state.version + 1
        const snapshotMac = this.crypto.generateSnapshotMac(
            activeKey.keyData,
            next.hash,
            patchVersion,
            collection,
        )
        const patchMac = this.crypto.generatePatchMac(
            activeKey.keyData,
            snapshotMac,
            mutations.map((entry) => entry.encrypted.valueMac),
            patchVersion,
            collection,
        )
        const patch = encode('SyncdPatch', {
            mutations: mutations.map((entry) => ({
                operation: entry.mutation.operation === 'remove' ? 1 : 0,
                record: {
                    keyId: { id: activeKey.keyId },
                    index: { blob: entry.encrypted.indexMac },
                    value: { blob: entry.encrypted.valueBlob },
                },
            })),
            snapshotMac,
            patchMac,
            keyId: { id: activeKey.keyId },
            ...(this.deviceIndex() !== undefined ? { deviceIndex: this.deviceIndex() } : {}),
        })
        return {
            patch,
            version: patchVersion,
            hash: next.hash,
            indexValueMap: next.indexValueMap,
        }
    }

    /**
     * Returns the state a collection would have after the given changes.
     *
     * @param base The current state.
     * @param mutations The changes.
     */
    computeNextCollectionState(
        base: AppStateCollectionState,
        mutations: readonly AppStateAppliedMutation[],
    ): { hash: Uint8Array; indexValueMap: Map<string, Uint8Array> } {
        const indexValueMap = new Map(base.indexValueMap)
        const addValues: Uint8Array[] = []
        const removeValues: Uint8Array[] = []
        for (const mutation of mutations) {
            const indexMacHex = toHex(mutation.indexMac)
            const existing = indexValueMap.get(indexMacHex)
            if (mutation.operation === 'remove') {
                if (!existing) continue
                indexValueMap.delete(indexMacHex)
                removeValues.push(existing)
                continue
            }
            if (existing) removeValues.push(existing)
            indexValueMap.set(indexMacHex, mutation.valueMac)
            addValues.push(mutation.valueMac)
        }
        const { hash } = this.crypto.ltHashSubtractThenAdd(base.hash, addValues, removeValues)
        return { hash, indexValueMap }
    }

    /**
     * Runs one sync round.
     *
     * @param options The options.
     */
    private async syncOnce(options: AppStateSyncOptions): Promise<AppStateSyncResult> {
        const collections = [
            ...new Set(options.collections ?? APP_STATE_DEFAULT_COLLECTIONS),
        ]
        const pendingByCollection = groupPendingMutations(options.pendingMutations ?? [])
        const results = new Map<string, AppStateCollectionResult>()
        const missingKeyIds = new Map<string, Uint8Array>()
        // The collections the server answered with a conflict the device
        // could not resolve on its own.
        const conflicted = new Set<string>()
        let pending = [...collections]

        for (let round = 0; round < APP_STATE_MAX_ROUNDS && pending.length > 0; round++) {
            const activeKey = this.ensureSyncKey()
            const requests = pending.map((collection) =>
                this.buildCollectionRequestDetailed(
                    collection,
                    pendingByCollection.get(collection) ?? [],
                    activeKey,
                ),
            )
            const response = await this.options.query(
                this.buildSyncIqNode(requests.map((request) => request.node)),
                options.timeoutMs,
            )
            const payloads = this.parseSyncResponse(response)
            const byCollection = new Map(payloads.map((payload) => [payload.collection, payload]))

            const refetch: string[] = []
            for (let i = 0; i < pending.length; i++) {
                const collection = pending[i]!
                const request = requests[i]!
                const payload = byCollection.get(collection)
                if (!payload) {
                    results.set(collection, {
                        collection,
                        state: APP_STATE_COLLECTION_STATES.ERROR_RETRY,
                        mutations: [],
                        uploaded: false,
                    })
                    continue
                }
                const outcome = await this.processCollection(
                    collection,
                    payload,
                    pendingByCollection.get(collection)?.length ?? 0,
                    request.outgoing,
                    request.skippedUpload,
                )
                results.set(collection, outcome.result)
                if (outcome.missingKeyId) {
                    missingKeyIds.set(toHex(outcome.missingKeyId), outcome.missingKeyId)
                }
                if (outcome.conflict) {
                    // The server is at another version, so the changes are
                    // not pushed again in this round: the device learns the
                    // state of the collection first and pushes its own
                    // changes in the next round.
                    conflicted.add(collection)
                    pendingByCollection.delete(collection)
                }
                if (outcome.refetch) {
                    refetch.push(collection)
                }
            }
            pending = refetch
        }

        for (const collection of collections) {
            const result = results.get(collection)
            if (!result) {
                results.set(collection, {
                    collection,
                    state: APP_STATE_COLLECTION_STATES.ERROR_RETRY,
                    mutations: [],
                    uploaded: false,
                })
                continue
            }
            if (conflicted.has(collection)) {
                // The server is at another version than the device, so the
                // changes of the collection are still pending: the round
                // that follows learns the state of the collection, and the
                // next sync pushes the changes again.
                result.state = APP_STATE_COLLECTION_STATES.CONFLICT
                result.uploaded = false
            }
        }

        const missing = [...missingKeyIds.values()]
        if (missing.length > 0 && this.options.onMissingKeys) {
            try {
                await this.options.onMissingKeys(missing)
            } catch (error) {
                this.warn(
                    `app-state: the request for the missing keys failed: ${
                        error instanceof Error ? error.message : String(error)
                    }`,
                )
            }
        }
        return {
            collections: collections.map((collection) => results.get(collection)!),
            missingKeyIds: missing,
        }
    }

    /**
     * Processes the answer of the server for one collection.
     *
     * @param collection The collection.
     * @param payload What the server answered.
     * @param pendingCount How many changes the client wanted to push.
     * @param outgoing The patch the client uploaded, when it uploaded one.
     * @param skippedUpload Whether the upload was skipped.
     */
    private async processCollection(
        collection: string,
        payload: AppStateCollectionPayload,
        pendingCount: number,
        outgoing?: {
            version: number
            hash: Uint8Array
            indexValueMap: Map<string, Uint8Array>
        },
        skippedUpload = false,
    ): Promise<{
        result: AppStateCollectionResult
        refetch: boolean
        conflict?: boolean
        missingKeyId?: Uint8Array
    }> {
        if (
            payload.state === APP_STATE_COLLECTION_STATES.ERROR_FATAL ||
            payload.state === APP_STATE_COLLECTION_STATES.ERROR_RETRY
        ) {
            return {
                result: {
                    collection,
                    state: payload.state,
                    mutations: [],
                    uploaded: pendingCount === 0,
                    ...(payload.version !== undefined ? { version: payload.version } : {}),
                },
                refetch: false,
            }
        }

        // A conflict means the server is at a version the device did not
        // expect. The collection is fetched again, so the device learns the
        // real state before it pushes its own changes.
        const isConflict =
            payload.state === APP_STATE_COLLECTION_STATES.CONFLICT ||
            payload.state === APP_STATE_COLLECTION_STATES.CONFLICT_HAS_MORE
        // A conflict is only a problem while the device still has changes
        // to push; without them the server simply won the race.
        const unresolvedConflict = isConflict && pendingCount > 0
        let refetch =
            payload.state === APP_STATE_COLLECTION_STATES.SUCCESS_HAS_MORE ||
            payload.state === APP_STATE_COLLECTION_STATES.CONFLICT_HAS_MORE ||
            unresolvedConflict

        const mutations: AppStateAppliedMutation[] = []
        // The client uploaded its own changes only when the server
        // accepted the patch it sent.
        let uploaded = pendingCount === 0
        try {
            if (payload.snapshotReference) {
                if (this.isMobilePrimary()) {
                    // The primary device owns the account state, so the
                    // snapshot the server sends is not applied.
                    this.warn(
                        `app-state: the snapshot of ${collection} is ignored on the primary device`,
                    )
                } else {
                    const downloader = this.options.downloadExternalBlob
                    if (!downloader) {
                        throw new Error(
                            `app-state: the snapshot of ${collection} needs a blob downloader`,
                        )
                    }
                    const bytes = await downloader(
                        collection,
                        'snapshot',
                        payload.snapshotReference,
                    )
                    const snapshot = decode('SyncdSnapshot', bytes) as unknown as AppStateSnapshot
                    mutations.push(...this.applySnapshot(collection, snapshot))
                }
            }
            if (payload.patches.length > 0) {
                // The patches are applied in the order of their versions: a
                // patch that arrives out of order would not fit the local
                // version.
                const patches = [...payload.patches].sort(
                    (left, right) => patchVersionOf(left) - patchVersionOf(right),
                )
                for (const patch of patches) {
                    const ready = await this.resolvePatchMutations(collection, patch)
                    mutations.push(...this.applyPatch(collection, ready))
                }
                if (outgoing && payload.version === outgoing.version) {
                    // The server merged the changes of the client with the
                    // changes of another device and ended at the version
                    // the patch of the client produced, so the upload was
                    // accepted.
                    uploaded = true
                }
            } else if (outgoing) {
                // The server accepted the patch the client uploaded, so the
                // local state advances to the version the patch produced.
                // The server names the version it ended at; a mismatch means
                // the server merged the changes of another device as well,
                // so the local state stays where it is and the changes are
                // pushed again in the next round.
                if (
                    payload.state === APP_STATE_COLLECTION_STATES.SUCCESS &&
                    payload.version === outgoing.version
                ) {
                    this.store.setCollectionState(collection, {
                        initialized: true,
                        version: outgoing.version,
                        hash: outgoing.hash,
                        indexValueMap: outgoing.indexValueMap,
                    })
                    uploaded = true
                } else if (payload.state === APP_STATE_COLLECTION_STATES.SUCCESS) {
                    this.warn(
                        `app-state: the server ended ${collection} at version ${String(
                            payload.version,
                        )} instead of ${String(outgoing.version)}`,
                    )
                    refetch = true
                }
            }
            if (
                !this.store.getCollectionState(collection).initialized &&
                payload.state === APP_STATE_COLLECTION_STATES.SUCCESS
            ) {
                // The server had nothing to send, so the device only learns
                // the version the collection is at.
                const state = this.store.getCollectionState(collection)
                this.store.setCollectionState(collection, {
                    initialized: true,
                    version: payload.version ?? state.version,
                    hash: state.hash,
                    indexValueMap: state.indexValueMap,
                })
            }

            if (skippedUpload && payload.state === APP_STATE_COLLECTION_STATES.SUCCESS) {
                // The upload was skipped because the device had no state of
                // the collection, so the round is repeated with what the
                // server sent.
                refetch = true
            }

            return {
                result: {
                    collection,
                    state: this.resolveCollectionState(payload.state, isConflict, pendingCount),
                    mutations,
                    uploaded: uploaded,
                    ...(payload.version !== undefined ? { version: payload.version } : {}),
                },
                refetch,
                conflict: unresolvedConflict,
            }
        } catch (error) {
            if (error instanceof AppStateMissingKeyError) {
                this.warn(
                    `app-state: ${collection} is blocked by a missing key (${toHex(error.keyId ?? new Uint8Array(0))})`,
                )
                return {
                    result: {
                        collection,
                        state: APP_STATE_COLLECTION_STATES.BLOCKED,
                        mutations,
                        uploaded: pendingCount === 0,
                        ...(payload.version !== undefined ? { version: payload.version } : {}),
                    },
                    refetch: false,
                    ...(error.keyId ? { missingKeyId: error.keyId } : {}),
                }
            }
            this.warn(
                `app-state: ${collection} could not be processed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            )
            return {
                result: {
                    collection,
                    state: APP_STATE_COLLECTION_STATES.ERROR_RETRY,
                    mutations,
                    uploaded: false,
                    ...(payload.version !== undefined ? { version: payload.version } : {}),
                },
                refetch: true,
            }
        }
    }

    /**
     * Resolves the mutations of a patch that the server stored on the CDN.
     *
     * A patch that carries too many mutations is uploaded to the CDN and the
     * stanza only holds a reference to it. The mutations are downloaded and
     * decoded before the patch is applied.
     *
     * @param collection The collection.
     * @param patch The patch.
     */
    private async resolvePatchMutations(
        collection: string,
        patch: AppStatePatch,
    ): Promise<AppStatePatch> {
        const inline = patch.mutations ?? []
        if (inline.length > 0 || !patch.externalMutations) return patch
        const downloader = this.options.downloadExternalBlob
        if (!downloader) {
            throw new Error(`app-state: the patch of ${collection} needs a blob downloader`)
        }
        const bytes = await downloader(collection, 'patch', patch.externalMutations)
        const decoded = decode('SyncdMutations', bytes) as {
            mutations?: AppStatePatch['mutations']
        }
        return { ...patch, mutations: decoded.mutations ?? [] }
    }

    /**
     * Resolves the state a collection ends in.
     *
     * A conflict is only a problem while the device still has changes to
     * push; without them the server simply won the race.
     *
     * @param state The state the server reported.
     * @param isConflict Whether the state is a conflict.
     * @param pendingCount How many changes the client wanted to push.
     */
    private resolveCollectionState(
        state: string,
        isConflict: boolean,
        pendingCount: number,
    ): string {
        if (!isConflict) return state
        if (state === APP_STATE_COLLECTION_STATES.CONFLICT_HAS_MORE) {
            return APP_STATE_COLLECTION_STATES.CONFLICT_HAS_MORE
        }
        return pendingCount > 0
            ? APP_STATE_COLLECTION_STATES.CONFLICT
            : APP_STATE_COLLECTION_STATES.SUCCESS
    }

    /**
     * Checks the MACs of a patch.
     *
     * The snapshot MAC is allowed to differ — the official clients tolerate
     * it — but the patch MAC covers the payload and must match.
     */
    private assertPatchMacs(
        collection: string,
        patch: AppStatePatch,
        keyData: Uint8Array,
        patchVersion: number,
        hash: Uint8Array,
        valueMacs: readonly Uint8Array[],
    ): void {
        const snapshotMac = patch.snapshotMac ?? new Uint8Array(0)
        const expectedSnapshotMac = this.crypto.generateSnapshotMac(
            keyData,
            hash,
            patchVersion,
            collection,
        )
        if (!equalBytes(expectedSnapshotMac, snapshotMac)) {
            this.warn(
                `app-state: the snapshot MAC of the patch for ${collection} does not match (tolerated)`,
            )
        }
        const patchMac = patch.patchMac ?? new Uint8Array(0)
        const expectedPatchMac = this.crypto.generatePatchMac(
            keyData,
            snapshotMac,
            valueMacs,
            patchVersion,
            collection,
        )
        if (!equalBytes(expectedPatchMac, patchMac)) {
            throw new Error(`app-state: the patch MAC of ${collection} does not match`)
        }
    }

    /** Whether this device is the primary device of a mobile session. */
    private isMobilePrimary(): boolean {
        return this.options.mobilePrimary === true
    }

    /** The index of this device. */
    private deviceIndex(): number | undefined {
        const meJid = this.options.getMeJid?.()
        if (!meJid) return undefined
        const match = /:(\d+)(?:@|$)/.exec(meJid)
        if (!match) return undefined
        const device = Number.parseInt(match[1]!, 10)
        return Number.isSafeInteger(device) ? device : undefined
    }

    /** Reports a problem that does not stop the sync. */
    private warn(message: string): void {
        this.options.logger?.log({ level: 'warn', message })
    }

    /** Reports a detail of the sync. */
    private log(message: string): void {
        this.options.logger?.log({ level: 'debug', message })
    }
}

/** The payload of one collection in a sync answer. */
export interface AppStateCollectionPayload {
    /** The collection. */
    collection: string
    /** The state the server reported. */
    state: string
    /** The version the collection has. */
    version?: number
    /** The patches the server sent. */
    patches: AppStatePatch[]
    /** The snapshot the server referenced. */
    snapshotReference?: AppStateExternalBlob
}

/** A decoded `SyncdPatch`. */
export interface AppStatePatch {
    /** The version the patch produces. */
    version?: { version?: number | bigint }
    /** The mutations the patch carries. */
    mutations?: {
        operation?: number
        record?: {
            index?: { blob?: Uint8Array }
            value?: { blob?: Uint8Array }
            keyId?: { id?: Uint8Array }
        }
    }[]
    /**
     * The mutations the server stored on the CDN.
     *
     * A patch that carries too many mutations is uploaded to the CDN, and
     * the stanza only holds a reference to it.
     */
    externalMutations?: AppStateExternalBlob
    /** The MAC over the resulting digest. */
    snapshotMac?: Uint8Array
    /** The MAC over the payload. */
    patchMac?: Uint8Array
    /** The id of the sync key the patch was encrypted for. */
    keyId?: { id?: Uint8Array }
    /** The exit code of the patch. */
    exitCode?: { code?: number | bigint; text?: string }
}

/** A decoded `SyncdSnapshot`. */
export interface AppStateSnapshot {
    /** The version of the snapshot. */
    version?: { version?: number | bigint }
    /** The records the snapshot carries. */
    records?: {
        index?: { blob?: Uint8Array }
        value?: { blob?: Uint8Array }
        keyId?: { id?: Uint8Array }
    }[]
    /** The MAC over the digest of the snapshot. */
    mac?: Uint8Array
    /** The id of the sync key the snapshot was encrypted for. */
    keyId?: { id?: Uint8Array }
}

/** A sync key of the store. */
export type { AppStateSyncKey } from './keys.js'

export { AppStateStore, type AppStateCollectionState } from './store.js'

/**
 * Groups the pending changes by collection.
 *
 * Only the last change of a record survives, because the server applies the
 * changes in order.
 */
function groupPendingMutations(
    pending: readonly AppStatePendingMutation[],
): Map<string, AppStatePendingMutation[]> {
    const grouped = new Map<string, AppStatePendingMutation[]>()
    for (const mutation of pending) {
        const list = grouped.get(mutation.collection)
        if (list) list.push(mutation)
        else grouped.set(mutation.collection, [mutation])
    }
    const compacted = new Map<string, AppStatePendingMutation[]>()
    for (const [collection, list] of grouped) {
        const seen = new Set<string>()
        const reversed: AppStatePendingMutation[] = []
        for (let i = list.length - 1; i >= 0; i--) {
            const mutation = list[i]!
            if (seen.has(mutation.index)) continue
            seen.add(mutation.index)
            reversed.push(mutation)
        }
        compacted.set(collection, reversed.reverse())
    }
    return compacted
}

/**
 * Reads the state of a `<collection/>` node.
 *
 * @param node The node.
 */
export function parseCollectionState(node: BinaryNode): string {
    const type = node.attrs.type
    const hasMorePatches = node.attrs.has_more_patches === 'true'
    if (type !== WA_IQ_TYPES.ERROR) {
        return hasMorePatches
            ? APP_STATE_COLLECTION_STATES.SUCCESS_HAS_MORE
            : APP_STATE_COLLECTION_STATES.SUCCESS
    }
    const errorNode = findNodeChild(node, WA_NODE_TAGS.ERROR)
    const code = errorNode?.attrs.code
    if (code === APP_STATE_ERROR_CODES.CONFLICT) {
        return hasMorePatches
            ? APP_STATE_COLLECTION_STATES.CONFLICT_HAS_MORE
            : APP_STATE_COLLECTION_STATES.CONFLICT
    }
    if (
        code === APP_STATE_ERROR_CODES.BAD_REQUEST ||
        code === APP_STATE_ERROR_CODES.NOT_FOUND ||
        code === APP_STATE_ERROR_CODES.NOT_ALLOWED ||
        code === APP_STATE_ERROR_CODES.NOT_ACCEPTABLE
    ) {
        return APP_STATE_COLLECTION_STATES.ERROR_FATAL
    }
    return APP_STATE_COLLECTION_STATES.ERROR_RETRY
}

/** Whether a collection name is one of the known collections. */
function isKnownCollection(name: string): boolean {
    return (Object.values(APP_STATE_COLLECTIONS) as string[]).includes(name)
}

/**
 * Reads the version of a snapshot or a patch.
 *
 * @param version The version message.
 * @param field The name of the field, for the error message.
 */
function readVersion(
    version: { version?: number | bigint } | undefined,
    field: string,
): number {
    const raw = version?.version
    if (raw === undefined || raw === null) {
        throw new Error(`app-state: ${field} is missing`)
    }
    const value = typeof raw === 'bigint' ? Number(raw) : raw
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error(`app-state: ${field} has an invalid version ${String(raw)}`)
    }
    return value
}

/**
 * Reads the version a patch produces.
 *
 * A patch without a version sorts first, so it is applied before the
 * patches that follow it.
 *
 * @param patch The patch.
 */
function patchVersionOf(patch: AppStatePatch): number {
    const raw = patch.version?.version
    if (raw === undefined || raw === null) return 0
    const value = typeof raw === 'bigint' ? Number(raw) : raw
    return Number.isSafeInteger(value) ? value : 0
}

/**
 * Reads the id of a sync key.
 *
 * @param keyId The key id message.
 */
function readKeyId(keyId: { id?: Uint8Array } | undefined): Uint8Array | null {
    const id = keyId?.id
    if (!id || id.length === 0) return null
    return id
}

/**
 * Reads the blob of an index or a value.
 *
 * @param holder The message that holds the blob.
 * @param field The name of the field, for the error message.
 */
function readBlob(
    holder: { blob?: Uint8Array } | undefined,
    field: string,
): Uint8Array {
    const blob = holder?.blob
    if (!blob) throw new Error(`app-state: ${field} is missing`)
    return blob
}

/**
 * Reads a byte field of a decoded message.
 *
 * @param value The value.
 */
function asBytes(value: unknown): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error('app-state: a blob reference is malformed')
    }
    return value
}

/**
 * Reads an optional byte field of a decoded message.
 *
 * @param value The value.
 */
function asOptionalBytes(value: unknown): Uint8Array | undefined {
    if (value === undefined || value === null) return undefined
    return asBytes(value)
}
