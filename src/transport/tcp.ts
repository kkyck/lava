/**
 * A raw TCP socket used by the WhatsApp *mobile* (WAP) transport.
 *
 * The native WhatsApp apps do not speak WebSocket: they open a plain TCP
 * connection to the WhatsApp servers and exchange the WhatsApp binary
 * protocol (a stream of length-prefixed, encrypted protobuf messages)
 * directly over it.
 *
 * This class is deliberately thin. It owns the socket lifecycle, hands raw
 * bytes to the caller and applies backpressure by pausing the socket when
 * the kernel buffer fills up.
 *
 * Design notes
 * ------------
 * - **No dependencies.** Built on `node:net` only.
 * - **No `Buffer` for stored data.** Inbound chunks are handed to the caller
 *   as `Uint8Array`; Node hands us `Buffer`s which are `Uint8Array`s, so no
 *   copy is required.
 * - **Exactly-once callbacks.** `onError` and `onClose` fire at most once
 *   per connection, and `onClose` always fires after `onError`.
 */

import { connect, type Socket } from 'node:net'

/** Default connection timeout in milliseconds. */
const DEFAULT_CONNECT_TIMEOUT_MS = 20_000

/** Grace period before a half-closed socket is forcibly destroyed. */
const CLOSE_GRACE_MS = 5_000

/** Configuration for {@link TcpSocket}. */
export interface TcpSocketOptions {
    /** Hostname or IP address of the server. */
    host: string
    /** TCP port of the server. */
    port: number
    /** Connection timeout in ms (default 20000). */
    connectTimeoutMs?: number
    /** Called with every chunk of inbound data. */
    onData?: (chunk: Uint8Array) => void
    /** Called once the connection is established. */
    onOpen?: () => void
    /** Called exactly once when the connection ends. */
    onClose?: (error?: Error) => void
    /** Called for connection and transport errors. */
    onError?: (error: Error) => void
}

/**
 * A connected (or connecting) TCP socket.
 *
 * ```ts
 * const socket = new TcpSocket({
 *     host: 'g.whatsapp.net',
 *     port: 443,
 *     onData: (chunk) => console.log('got', chunk.length, 'bytes'),
 * })
 * await socket.connect()
 * socket.write(payload)
 * ```
 */
export class TcpSocket {
    private readonly options: TcpSocketOptions
    private readonly connectTimeoutMs: number

    private state: 'connecting' | 'open' | 'closed' = 'connecting'
    private socket: Socket | undefined
    private started = false
    private finished = false

    private connectPromise: Promise<void> | null = null
    private resolveConnect: (() => void) | null = null
    private rejectConnect: ((error: Error) => void) | null = null

    private connectTimer: NodeJS.Timeout | null = null
    private closeTimer: NodeJS.Timeout | null = null
    /** Whether the socket is currently paused because of backpressure. */
    private paused = false
    /** The error that caused the connection to end, if any. */
    private failure: Error | undefined

    /** Called with every chunk of inbound data. */
    onData?: (chunk: Uint8Array) => void
    /** Called once the connection is established. */
    onOpen?: () => void
    /** Called exactly once when the connection ends. */
    onClose?: (error?: Error) => void
    /** Called for connection and transport errors. */
    onError?: (error: Error) => void

    constructor(options: TcpSocketOptions) {
        this.options = options
        // The handlers may also be assigned after construction; the options
        // simply seed the initial values.
        this.onData = options.onData
        this.onOpen = options.onOpen
        this.onClose = options.onClose
        this.onError = options.onError
        this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS
    }

    /** `connecting` before the socket is up, `open` afterwards, `closed` at the end. */
    get readyState(): 'connecting' | 'open' | 'closed' {
        return this.state
    }

    /**
     * Opens the connection.
     *
     * @throws The returned promise rejects when the socket cannot be opened
     *   or the connection times out.
     */
    connect(): Promise<void> {
        if (this.started) {
            return (
                this.connectPromise ??
                Promise.reject(new Error('TcpSocket: connect() has already been called'))
            )
        }
        this.started = true
        this.connectPromise = new Promise<void>((resolve, reject) => {
            this.resolveConnect = resolve
            this.rejectConnect = reject
        })
        try {
            this.openSocket()
        } catch (error) {
            this.failConnect(toError(error))
        }
        return this.connectPromise
    }

    /**
     * Writes a chunk of data.
     *
     * When the kernel buffer is full the socket is paused so that the peer
     * stops sending; it is resumed on `'drain'`. This keeps the memory
     * footprint bounded without dropping data.
     *
     * @throws When the socket is not open.
     */
    write(data: Uint8Array): void {
        if (this.state !== 'open') {
            throw new Error(
                `TcpSocket: cannot write, the socket is "${this.state}" instead of "open"`,
            )
        }
        const socket = this.socket
        if (!socket) {
            throw new Error('TcpSocket: cannot write, the socket is gone')
        }
        const accepted = socket.write(data)
        if (!accepted && !this.paused) {
            // Stop reading until the write buffer drains again.
            this.paused = true
            socket.pause()
            socket.once('drain', () => {
                this.paused = false
                socket.resume()
            })
        }
    }

    /** Closes the connection. */
    close(): void {
        if (this.state === 'closed') return
        if (this.state === 'connecting') {
            this.failConnect(new Error('TcpSocket: closed during the connection attempt'))
            this.destroy()
            return
        }
        const socket = this.socket
        if (!socket) {
            this.finish()
            return
        }
        // Half-close gracefully; the 'close' event finishes the teardown.
        socket.end()
        this.closeTimer = setTimeout(() => {
            this.closeTimer = null
            this.destroy()
        }, CLOSE_GRACE_MS)
        this.closeTimer.unref()
    }

    // ─── Connection setup ─────────────────────────────────────────────────────

    /** Creates the socket and wires the event handlers. */
    private openSocket(): void {
        const socket = connect({ host: this.options.host, port: this.options.port })
        this.socket = socket
        socket.setNoDelay(true)

        socket.on('connect', () => {
            this.clearConnectTimer()
            this.state = 'open'
            const resolve = this.resolveConnect
            this.resolveConnect = null
            this.rejectConnect = null
            resolve?.()
            this.onOpen?.()
        })
        socket.on('data', (chunk: Buffer) => {
            this.onData?.(chunk)
        })
        socket.on('error', (error: Error) => {
            this.handleError(error)
        })
        socket.on('close', () => {
            this.finish()
        })

        this.connectTimer = setTimeout(() => {
            this.connectTimer = null
            this.handleError(
                new Error(
                    `TcpSocket: connection to ${this.options.host}:${this.options.port} timed out after ${this.connectTimeoutMs}ms`,
                ),
            )
        }, this.connectTimeoutMs)
        // The timer must not keep the process alive on its own.
        this.connectTimer.unref()
    }

    // ─── Teardown ─────────────────────────────────────────────────────────────

    /** Handles a socket level error. */
    private handleError(error: Error): void {
        if (this.finished) return
        this.failure = error
        this.onError?.(error)
        this.failConnect(error)
        this.destroy()
    }

    /** Destroys the socket and finishes the connection. */
    private destroy(): void {
        this.clearConnectTimer()
        this.clearCloseTimer()
        const socket = this.socket
        this.socket = undefined
        this.state = 'closed'
        if (socket) {
            socket.removeAllListeners()
            // A late socket error must not become an uncaught exception.
            socket.on('error', () => {})
            socket.destroy()
        }
        this.finish()
    }

    /** Emits `onClose` exactly once. */
    private finish(): void {
        if (this.finished) return
        this.finished = true
        this.state = 'closed'
        this.socket = undefined
        this.clearConnectTimer()
        this.clearCloseTimer()
        this.onClose?.(this.failure)
    }

    /** Rejects the pending `connect()` promise, if any. */
    private failConnect(error: Error): void {
        const reject = this.rejectConnect
        this.rejectConnect = null
        this.resolveConnect = null
        reject?.(error)
    }

    /** Clears the connection timeout, if it is armed. */
    private clearConnectTimer(): void {
        if (!this.connectTimer) return
        clearTimeout(this.connectTimer)
        this.connectTimer = null
    }

    /** Clears the closing grace timer, if it is armed. */
    private clearCloseTimer(): void {
        if (!this.closeTimer) return
        clearTimeout(this.closeTimer)
        this.closeTimer = null
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/** Normalises an unknown thrown value into an `Error`. */
function toError(value: unknown): Error {
    return value instanceof Error ? value : new Error(String(value))
}
