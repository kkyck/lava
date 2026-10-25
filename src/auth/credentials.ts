/**
 * Credential storage.
 *
 * A WhatsApp session consists of a *Noise* identity key pair, the Signal
 * identity key pair, a signed pre-key and — once the device has been paired
 * — the account's own JID and the server's static key.
 *
 * The credential store is deliberately tiny and pluggable: the library ships
 * an in-memory store and a JSON file store, and users can implement the
 * {@link CredentialStore} interface to keep the material in a keychain or an
 * encrypted database.
 *
 * @sensitive Every value handled here is private key material. Never log it
 * and never serialise it with `JSON.stringify` without the helpers below.
 */

import { randomBytes } from 'node:crypto'
import { readFile, writeFile, mkdir, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'

import type { AppStateStoreSnapshot } from '../appstate/store.js'
import type {
    SerializedSenderKeyState,
    SerializedSignalSession,
} from '../signal/persistence.js'

/** A serialised key pair. */
export interface StoredKeyPair {
    /** The public key, base64 encoded. */
    pub: string
    /** The private key, base64 encoded. */
    priv: string
}

/** The persisted shape of a device's credentials. */
export interface CredentialSnapshot {
    /** Snapshot format version. */
    version: number
    /** The Noise identity key pair. */
    noiseKeyPair: StoredKeyPair
    /** The Signal identity key pair. */
    identityKeyPair: StoredKeyPair
    /** The Signal registration id. */
    registrationId: number
    /** The current signed pre-key. */
    signedPreKey: {
        /** The pre-key id. */
        id: number
        /** The pre-key pair. */
        keyPair: StoredKeyPair
        /** The XEdDSA signature, base64 encoded. */
        signature: string
    }
    /**
     * The one-time pre-keys of this device that have not been consumed yet.
     *
     * Uploaded pre-keys stay in the snapshot: the server keeps handing them
     * out, and the device must still be able to decrypt the pre-key message
     * that uses them.
     */
    preKeys: { id: number; keyPair: StoredKeyPair }[]
    /**
     * The id of the first pre-key that has not been uploaded yet.
     *
     * The ids are handed out sequentially, so this is a cursor into the
     * pre-key id space.
     */
    firstUnuploadedPreKeyId?: number
    /**
     * The next pre-key id to hand out.
     *
     * The counter must never go back, or a pre-key id that was already used
     * would be handed out twice.
     */
    nextPreKeyId?: number
    /**
     * The next signed pre-key id to hand out.
     *
     * Signed pre-keys live in their own id namespace, so their counter is
     * independent of the one-time pre-key counter.
     */
    nextSignedPreKeyId?: number
    /**
     * Whether the server currently holds a batch of our pre-keys.
     *
     * While this flag is set, the client does not upload pre-keys again: the
     * server tells the client when its pool runs low with an
     * `<notification type="encrypt"><count/></notification>` stanza.
     */
    serverHasPreKeys?: boolean
    /** The account's phone-number JID, once paired. */
    meJid?: string
    /** The account's LID, once known. */
    meLid?: string
    /** The account's display name. */
    meDisplayName?: string
    /** The push name shown to other users. */
    pushName?: string
    /** The server's Noise static key, used for a resumed handshake. */
    serverStaticKey?: string
    /** The ADV secret key used to sign the device attestation. */
    advSecretKey?: string
    /** The companion's encrypted static key, for companion devices. */
    companionEncStatic?: string
    /** The transport the device is paired for. */
    transport?: 'mobile' | 'web'
    /** The number of successful logins since the device was paired. */
    loginCounter?: number
    /** The timestamp of the last successful connection. */
    lastSuccessTs?: number
    /** The mobile device profile, for mobile transport sessions. */
    deviceInfo?: {
        /** The app version reported to the server. */
        appVersion: string
        /** The device's marketing name. */
        device: string
        /** The OS version. */
        osVersion: string
        /** The OS build number. */
        osBuildNumber: string
        /** The manufacturer. */
        manufacturer: string
        /** The platform the device announces. */
        os?: 'android' | 'ios'
        /** The device board (Android). */
        deviceBoard?: string
        /** The mobile country code. */
        mcc?: string
        /** The mobile network code. */
        mnc?: string
    }
    /**
     * The app-state store: the sync keys and the state of the collections.
     *
     * The state has to survive a restart, otherwise the client would ask the
     * server for a fresh snapshot every time it connects.
     */
    appState?: AppStateStoreSnapshot
    /**
     * The double-ratchet sessions of the device, keyed by Signal address.
     *
     * The ratchet state cannot be recreated from the key material: the root
     * key, the chain keys and the ratchet keys all evolve with every
     * message. A device that forgets them cannot decrypt the next message
     * of an established conversation, so they have to survive a restart.
     */
    sessions?: Record<string, SerializedSignalSession>
    /**
     * The sender keys of the group chats, keyed by group id.
     *
     * The chain key of a sender key advances with every message, and the
     * received keys are the only way to decrypt a group message at all, so
     * they have to survive a restart as well.
     */
    senderKeys?: SerializedSenderKeyState
}

/**
 * Encodes bytes as standard base64.
 *
 * @param value The bytes.
 */
export function toBase64(value: Uint8Array): string {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64')
}

/**
 * Decodes standard base64 into bytes.
 *
 * @param value The base64 text.
 */
export function fromBase64(value: string): Uint8Array {
    const buffer = Buffer.from(value, 'base64')
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
}

/**
 * A store that persists the device's credentials.
 */
export interface CredentialStore {
    /**
     * Loads the stored credentials.
     *
     * @returns The snapshot, or `null` when nothing is stored.
     */
    load(): Promise<CredentialSnapshot | null>
    /**
     * Persists the credentials.
     *
     * @param snapshot The snapshot to store.
     */
    save(snapshot: CredentialSnapshot): Promise<void>
    /** Removes the stored credentials. */
    clear(): Promise<void>
}

/**
 * An in-memory credential store.
 *
 * Nothing survives a process restart; use it for tests and short-lived
 * tools.
 */
export class MemoryCredentialStore implements CredentialStore {
    private snapshot: CredentialSnapshot | null = null

    /** Loads the stored credentials. */
    async load(): Promise<CredentialSnapshot | null> {
        return this.snapshot
    }

    /**
     * Persists the credentials.
     *
     * @param snapshot The snapshot.
     */
    async save(snapshot: CredentialSnapshot): Promise<void> {
        this.snapshot = snapshot
    }

    /** Removes the stored credentials. */
    async clear(): Promise<void> {
        this.snapshot = null
    }
}

/**
 * A credential store backed by a JSON file.
 *
 * The file is written with `0600` permissions, and the write is atomic
 * (write to a temporary file, then rename) so a crash cannot leave a
 * half-written key file behind.
 */
export class FileCredentialStore implements CredentialStore {
    private readonly path: string

    /**
     * @param path The file path.
     */
    constructor(path: string) {
        this.path = path
    }

    /** Loads the stored credentials. */
    async load(): Promise<CredentialSnapshot | null> {
        let raw: string
        try {
            raw = await readFile(this.path, 'utf8')
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
            throw error
        }
        try {
            return JSON.parse(raw) as CredentialSnapshot
        } catch {
            throw new Error(`credential file at ${this.path} is corrupt`)
        }
    }

    /**
     * Persists the credentials.
     *
     * @param snapshot The snapshot.
     */
    async save(snapshot: CredentialSnapshot): Promise<void> {
        await mkdir(dirname(this.path), { recursive: true })
        const temporary = `${this.path}.${randomBytes(6).toString('hex')}.tmp`
        await writeFile(temporary, JSON.stringify(snapshot), { mode: 0o600 })
        const { rename } = await import('node:fs/promises')
        await rename(temporary, this.path)
    }

    /** Removes the stored credentials. */
    async clear(): Promise<void> {
        try {
            await unlink(this.path)
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        }
    }
}
