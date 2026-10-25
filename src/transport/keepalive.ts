/**
 * The keepalive of a connection.
 *
 * WhatsApp closes a socket that says nothing for a while. A client that
 * only talks when the user sends something therefore loses its connection
 * every few minutes — the server drops the socket long before the next
 * message.
 *
 * The keepalive pings the server with a `w:p` IQ every few seconds. The
 * ping answers with the server's clock, so it doubles as a clock-skew
 * measurement, and a ping that never comes back proves that the socket is
 * dead long before the server would have noticed.
 *
 * The interval carries a little jitter: a fleet of clients that all ping
 * at the same moment looks like a denial-of-service to the server, and the
 * jitter keeps the load spread out.
 */

import { WA_DEFAULTS, WA_IQ_TYPES, WA_NODE_TAGS, WA_XMLNS } from '../protocol/constants.js'
import type { BinaryNode } from '../transport/binary/types.js'

/** The share of the interval the jitter may span. */
const DEFAULT_JITTER_RATIO = 0.1

/** The smallest jitter the keepalive adds, in milliseconds. */
const DEFAULT_MIN_JITTER_MS = 250

/** Configuration of a {@link KeepAlive}. */
export interface KeepAliveConfig {
    /** Sends the ping and waits for the answer. */
    query: (node: BinaryNode, timeoutMs?: number) => Promise<BinaryNode>
    /** The interval between two pings, in milliseconds. */
    intervalMs?: number
    /** How long a ping may take before the socket is considered dead. */
    timeoutMs?: number
    /** Called when a ping fails — the socket is probably dead. */
    onFailure?: (error: Error) => void
    /** Called with the clock skew the server reported, in milliseconds. */
    onClockSkewMs?: (skewMs: number) => void
}

/**
 * Keeps a connection alive.
 */
export class KeepAlive {
    private readonly query: KeepAliveConfig['query']
    private readonly intervalMs: number
    private readonly timeoutMs: number
    private readonly onFailure: KeepAliveConfig['onFailure']
    private readonly onClockSkewMs: KeepAliveConfig['onClockSkewMs']
    private timer: NodeJS.Timeout | null = null
    private generation = 0
    private inFlight = false

    /**
     * @param config The keepalive configuration.
     */
    constructor(config: KeepAliveConfig) {
        this.query = config.query
        this.intervalMs = config.intervalMs ?? WA_DEFAULTS.HEALTH_CHECK_INTERVAL_MS
        this.timeoutMs = config.timeoutMs ?? WA_DEFAULTS.DEAD_SOCKET_TIMEOUT_MS
        this.onFailure = config.onFailure
        this.onClockSkewMs = config.onClockSkewMs
    }

    /** Starts the keepalive. */
    start(): void {
        this.generation += 1
        this.inFlight = false
        this.schedule(this.generation)
    }

    /** Stops the keepalive. */
    stop(): void {
        this.generation += 1
        this.inFlight = false
        if (this.timer) {
            clearTimeout(this.timer)
            this.timer = null
        }
    }

    /**
     * Schedules the next ping.
     *
     * @param generation The generation the schedule belongs to; a ping of an
     *   older generation is dropped.
     */
    private schedule(generation: number): void {
        if (generation !== this.generation) return
        if (this.timer) {
            clearTimeout(this.timer)
            this.timer = null
        }
        const jitterWindow = Math.max(
            DEFAULT_MIN_JITTER_MS,
            Math.floor(this.intervalMs * DEFAULT_JITTER_RATIO),
        )
        const offset = Math.floor(Math.random() * (jitterWindow * 2 + 1) - jitterWindow)
        this.timer = setTimeout(() => {
            this.timer = null
            void this.run(generation)
        }, Math.max(1, this.intervalMs + offset))
        /**
         * The timer must not keep the process alive on its own: the socket
         * does that already, and a client that is disconnected has to be able
         * to let the host process exit.
         */
        this.timer.unref?.()
    }

    /**
     * Sends one ping.
     *
     * @param generation The generation the ping belongs to.
     */
    private async run(generation: number): Promise<void> {
        if (generation !== this.generation) return
        if (this.inFlight) {
            this.schedule(generation)
            return
        }
        this.inFlight = true
        const startedAt = Date.now()
        try {
            const response = await this.query(
                {
                    tag: WA_NODE_TAGS.IQ,
                    attrs: {
                        to: WA_DEFAULTS.HOST_DOMAIN,
                        type: WA_IQ_TYPES.GET,
                        xmlns: WA_XMLNS.WHATSAPP_PING,
                    },
                },
                this.timeoutMs,
            )
            const latencyMs = Date.now() - startedAt
            const serverT = Number(response.attrs.t ?? '')
            if (this.onClockSkewMs && Number.isFinite(serverT) && serverT > 0) {
                // The server answers with its own clock; half the round trip
                // is the network delay, so the rest is the difference
                // between the two clocks.
                const halfRttMs = Math.round(latencyMs / 2)
                this.onClockSkewMs(serverT * 1000 - (startedAt + halfRttMs))
            }
        } catch (error) {
            if (generation === this.generation) {
                this.onFailure?.(
                    error instanceof Error ? error : new Error(String(error)),
                )
            }
            this.inFlight = false
            this.schedule(generation)
            return
        }
        this.inFlight = false
        this.schedule(generation)
    }
}
