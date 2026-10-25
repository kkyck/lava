/**
 * The cache of the messages that were sent recently.
 *
 * A peer that cannot decrypt a message asks for it to be sent again with a
 * `<receipt type="retry">` stanza. The answer needs the plaintext of the
 * original message — the ciphertext cannot be reused, because the peer
 * could not read it in the first place.
 *
 * The plaintexts are therefore kept for a short while. They never leave the
 * process, and the entries are dropped as soon as they are older than the
 * time-to-live or when the cache grows past its limit.
 */

/** One outbound message that may have to be sent again. */
export interface OutboundMessage {
    /** The recipient: a user JID or a group JID. */
    to: string
    /** The padded plaintext of the message. */
    plaintext: Uint8Array
    /** The stanza type of the message (`text`, `image`, …). */
    type: string
    /** Whether the message was addressed to a group. */
    isGroup: boolean
    /** The media type, when the message carries media. */
    mediatype?: string
    /** When the message was sent, in milliseconds since the epoch. */
    sentAtMs: number
}

/** The options of the outbound cache. */
export interface OutboundMessageCacheOptions {
    /** How long a message stays replayable, in milliseconds. */
    ttlMs?: number
    /** The largest number of messages that are kept. */
    maxEntries?: number
}

/** The default lifetime of a cached message, in milliseconds. */
export const OUTBOUND_MESSAGE_TTL_MS = 5 * 60 * 1000

/** The default number of cached messages. */
export const OUTBOUND_MESSAGE_MAX_ENTRIES = 256

/**
 * A small cache of the messages that were sent recently.
 *
 * The cache is bounded in both time and size, so a client that talks a lot
 * does not grow without end.
 */
export class OutboundMessageCache {
    private readonly entries = new Map<string, OutboundMessage>()
    private readonly ttlMs: number
    private readonly maxEntries: number

    /**
     * @param options The cache options.
     */
    constructor(options: OutboundMessageCacheOptions = {}) {
        this.ttlMs = options.ttlMs ?? OUTBOUND_MESSAGE_TTL_MS
        this.maxEntries = options.maxEntries ?? OUTBOUND_MESSAGE_MAX_ENTRIES
    }

    /**
     * Remembers a sent message.
     *
     * @param id The message id.
     * @param message The message.
     */
    set(id: string, message: OutboundMessage): void {
        this.entries.delete(id)
        this.entries.set(id, message)
        this.prune()
    }

    /**
     * Returns a sent message.
     *
     * @param id The message id.
     */
    get(id: string): OutboundMessage | undefined {
        const entry = this.entries.get(id)
        if (!entry) return undefined
        if (Date.now() - entry.sentAtMs > this.ttlMs) {
            this.entries.delete(id)
            return undefined
        }
        return entry
    }

    /**
     * Forgets a sent message.
     *
     * @param id The message id.
     */
    delete(id: string): void {
        this.entries.delete(id)
    }

    /** Drops every cached message. */
    clear(): void {
        this.entries.clear()
    }

    /** The number of cached messages. */
    get size(): number {
        return this.entries.size
    }

    /** Drops the entries that are too old, and the oldest ones when full. */
    private prune(): void {
        const now = Date.now()
        for (const [id, entry] of this.entries) {
            if (now - entry.sentAtMs > this.ttlMs) this.entries.delete(id)
        }
        while (this.entries.size > this.maxEntries) {
            const oldest = this.entries.keys().next()
            if (oldest.done) break
            this.entries.delete(oldest.value)
        }
    }
}
