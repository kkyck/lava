/**
 * The app-state store.
 *
 * The store keeps two things: the inventory of sync keys the device knows
 * about, and the state of every collection it has synchronised (the version,
 * the LT-hash and the value MAC of every record).
 *
 * The store is deliberately plain: a map of maps, no database and no
 * reflection. It can be serialised into a plain JSON object, which is what
 * the client writes into the credential file, so the state survives a
 * restart without pulling in a storage engine.
 */

import { fromHex, toHex } from '../crypto/primitives.js'
import { APP_STATE_EMPTY_LT_HASH } from './constants.js'
import { pickActiveSyncKey, type AppStateSyncKey } from './keys.js'

/** The state of one collection. */
export interface AppStateCollectionState {
    /** Whether the collection was ever synchronised. */
    initialized: boolean
    /** The version of the collection. */
    version: number
    /** The LT-hash digest of the collection. */
    hash: Uint8Array
    /** The value MAC of every record, keyed by the hex of its index MAC. */
    indexValueMap: Map<string, Uint8Array>
}

/** The serialised form of the store. */
export interface AppStateStoreSnapshot {
    /** The sync keys, base64 free (hex) encoded. */
    keys: { keyId: string; keyData: string; timestamp: number }[]
    /** The state of every collection. */
    collections: Record<
        string,
        { version: number; hash: string; values: Record<string, string> }
    >
}

/**
 * Creates the empty state of a collection.
 */
export function emptyCollectionState(): AppStateCollectionState {
    return {
        initialized: false,
        version: 0,
        hash: APP_STATE_EMPTY_LT_HASH,
        indexValueMap: new Map(),
    }
}

/** The in-memory app-state store. */
export class AppStateStore {
    private readonly keys = new Map<string, AppStateSyncKey>()
    private readonly collections = new Map<string, AppStateCollectionState>()

    /**
     * Lists every sync key the device knows about.
     */
    listKeys(): AppStateSyncKey[] {
        return [...this.keys.values()]
    }

    /**
     * Looks a sync key up by its id.
     *
     * @param keyId The key id.
     */
    getKey(keyId: Uint8Array): AppStateSyncKey | undefined {
        return this.keys.get(toHex(keyId))
    }

    /**
     * Adds sync keys to the inventory.
     *
     * A key that is already known is replaced, because the peers may have
     * rotated their key and sent the new secret under the same id.
     *
     * @param keys The keys to add.
     * @returns The number of keys that were new.
     */
    upsertKeys(keys: readonly AppStateSyncKey[]): number {
        let added = 0
        for (const key of keys) {
            const id = toHex(key.keyId)
            if (!this.keys.has(id)) added += 1
            this.keys.set(id, key)
        }
        return added
    }

    /**
     * Removes a sync key.
     *
     * @param keyId The key id.
     * @returns Whether the key was there.
     */
    removeKey(keyId: Uint8Array): boolean {
        return this.keys.delete(toHex(keyId))
    }

    /**
     * Returns the key the device should write with.
     */
    getActiveSyncKey(): AppStateSyncKey | null {
        return pickActiveSyncKey(this.keys.values())
    }

    /**
     * Returns the state of a collection.
     *
     * @param collection The collection name.
     */
    getCollectionState(collection: string): AppStateCollectionState {
        return this.collections.get(collection) ?? emptyCollectionState()
    }

    /**
     * Stores the state of a collection.
     *
     * @param collection The collection name.
     * @param state The new state.
     */
    setCollectionState(collection: string, state: AppStateCollectionState): void {
        this.collections.set(collection, state)
    }

    /**
     * Forgets the state of a collection, so the next round asks the server
     * for a fresh snapshot.
     *
     * @param collection The collection name.
     */
    clearCollectionState(collection: string): void {
        this.collections.delete(collection)
    }

    /** Forgets everything. */
    clear(): void {
        this.keys.clear()
        this.collections.clear()
    }

    /**
     * Serialises the store.
     */
    toSnapshot(): AppStateStoreSnapshot {
        const keys = this.listKeys().map((key) => ({
            keyId: toHex(key.keyId),
            keyData: toHex(key.keyData),
            timestamp: key.timestamp,
        }))
        const collections: AppStateStoreSnapshot['collections'] = {}
        for (const [name, state] of this.collections) {
            const values: Record<string, string> = {}
            for (const [indexMac, valueMac] of state.indexValueMap) {
                values[indexMac] = toHex(valueMac)
            }
            collections[name] = {
                version: state.version,
                hash: toHex(state.hash),
                values,
            }
        }
        return { keys, collections }
    }

    /**
     * Restores a store from a serialised snapshot.
     *
     * @param snapshot The snapshot.
     */
    static fromSnapshot(snapshot: AppStateStoreSnapshot | undefined | null): AppStateStore {
        const store = new AppStateStore()
        store.mergeSnapshot(snapshot)
        return store
    }

    /**
     * Merges a serialised snapshot into the store.
     *
     * @param snapshot The snapshot.
     */
    mergeSnapshot(snapshot: AppStateStoreSnapshot | undefined | null): void {
        if (!snapshot) return
        for (const key of snapshot.keys ?? []) {
            this.keys.set(key.keyId, {
                keyId: fromHex(key.keyId),
                keyData: fromHex(key.keyData),
                timestamp: key.timestamp,
            })
        }
        for (const [name, state] of Object.entries(snapshot.collections ?? {})) {
            const indexValueMap = new Map<string, Uint8Array>()
            for (const [indexMac, valueMac] of Object.entries(state.values ?? {})) {
                indexValueMap.set(indexMac, fromHex(valueMac))
            }
            this.collections.set(name, {
                initialized: true,
                version: state.version,
                hash: fromHex(state.hash),
                indexValueMap,
            })
        }
    }
}
