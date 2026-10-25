/**
 * The QR rotation of a pairing session.
 *
 * The server hands out a handful of pairing references with every
 * `<pair-device>` stanza. Each reference is valid for a limited time, so the
 * client walks through them and shows the next QR code as the current one
 * expires. When the last reference is used up the server sends a new
 * `<pair-device>` stanza and the cycle starts over.
 *
 * The first reference of a fresh set lives for a minute (the user needs time
 * to find the phone), every following one for twenty seconds.
 */

import { WA_DEFAULTS } from '../protocol/constants.js'

/** Configuration of a {@link QrFlow}. */
export interface QrFlowConfig {
    /** Builds the QR payload of a reference. */
    buildQr: (ref: string) => string
    /** Called with every QR payload and its lifetime. */
    emitQr: (qr: string, ttlMs: number) => void
    /** The lifetime of the first reference, in milliseconds. */
    initialTtlMs?: number
    /** The lifetime of every following reference, in milliseconds. */
    rotationTtlMs?: number
}

/**
 * Keeps track of the pairing references and of the QR code that is shown.
 */
export class QrFlow {
    private readonly config: QrFlowConfig
    private refs: string[] = []
    private index = 0
    private timer: NodeJS.Timeout | null = null
    /** The reference of the QR code that is on screen, if any. */
    private current: string | null = null
    /** When the QR code on screen expires. */
    private currentExpiresAt = 0

    /**
     * @param config The flow configuration.
     */
    constructor(config: QrFlowConfig) {
        this.config = config
    }

    /** Whether a QR code is available. */
    get hasQr(): boolean {
        if (this.current !== null && Date.now() < this.currentExpiresAt) return true
        return this.index < this.refs.length
    }

    /** The number of references that have not been used yet. */
    get remaining(): number {
        return Math.max(0, this.refs.length - this.index)
    }

    /**
     * Replaces the references with a fresh set and shows the first one.
     *
     * @param refs The references the server handed out.
     */
    setRefs(refs: string[]): void {
        this.clear()
        this.refs = [...refs]
        this.rotate()
    }

    /**
     * Shows the current QR code again.
     *
     * The server asks for a refresh when the reference it handed out was
     * already used; the same reference is shown once more.
     *
     * @returns `true` when a QR code was shown.
     */
    refreshCurrentQr(): boolean {
        if (this.index === 0) return false
        const ref = this.refs[this.index - 1]
        if (ref === undefined) return false
        const ttlMs = this.ttlFor(this.remaining)
        this.current = ref
        this.currentExpiresAt = Date.now() + ttlMs
        this.config.emitQr(this.config.buildQr(ref), ttlMs)
        return true
    }

    /** Drops the references and stops the rotation. */
    clear(): void {
        if (this.timer) {
            clearTimeout(this.timer)
            this.timer = null
        }
        this.refs = []
        this.index = 0
        this.current = null
        this.currentExpiresAt = 0
    }

    /** Shows the next reference and schedules the one after it. */
    private rotate(): void {
        const ref = this.refs[this.index]
        if (ref === undefined) {
            this.clear()
            return
        }
        this.index += 1
        const ttlMs = this.ttlFor(this.remaining)
        this.current = ref
        this.currentExpiresAt = Date.now() + ttlMs
        this.config.emitQr(this.config.buildQr(ref), ttlMs)
        if (this.index < this.refs.length) {
            this.timer = setTimeout(() => {
                this.timer = null
                this.rotate()
            }, ttlMs)
        } else {
            // The last reference is on screen; when it expires there is
            // nothing left to show.
            this.timer = setTimeout(() => {
                this.timer = null
                this.current = null
                this.currentExpiresAt = 0
            }, ttlMs)
        }
        this.timer.unref?.()
    }

    /**
     * The lifetime of the current reference.
     *
     * @param remaining The number of references that are left.
     */
    private ttlFor(remaining: number): number {
        const initial = this.config.initialTtlMs ?? WA_DEFAULTS.QR_INITIAL_TTL_MS
        const rotation = this.config.rotationTtlMs ?? WA_DEFAULTS.QR_ROTATION_TTL_MS
        return remaining >= 5 ? initial : rotation
    }
}
