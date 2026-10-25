/**
 * A minimal, allocation-conscious RFC 6455 WebSocket client.
 *
 * This is the transport used by the WhatsApp *Web* client: WhatsApp exposes
 * a WebSocket endpoint (`wss://web.whatsapp.com/ws/chat`) that carries the
 * same binary protocol the native apps speak over TCP.
 *
 * Design notes
 * ------------
 * - **No dependencies.** Everything is built on `node:tls` / `node:net` and
 *   `node:crypto`, so the library keeps its zero-runtime-dependency promise.
 * - **No `Buffer` for stored data.** Every byte buffer that outlives a single
 *   call is a plain `Uint8Array`; `Buffer` is only used transiently for
 *   `crypto` interop.
 * - **Manual handshake.** The HTTP/1.1 Upgrade dance is performed by hand so
 *   we can validate `Sec-WebSocket-Accept` and so that no HTTP parser (and
 *   no header allocation) sits in the hot path.
 * - **Masking.** RFC 6455 requires every client→server frame to be masked
 *   with a fresh 4-byte key. We do that with a masking loop instead of an
 *   intermediate copy.
 * - **Backpressure.** Outbound frames are queued and flushed only while the
 *   socket accepts data; the queue resumes on `'drain'`.
 *
 * The client speaks both `wss://` (TLS) and `ws://` (plain TCP) so it can be
 * exercised against a local test server without certificates.
 */

import { createHash, randomBytes } from 'node:crypto'
import { connect as netConnect, isIP, type Socket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'

/** The magic GUID from RFC 6455 §1.3 used to derive `Sec-WebSocket-Accept`. */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

/** Default handshake timeout in milliseconds. */
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 20_000

/** Default maximum size of a single inbound message (16 MiB). */
const DEFAULT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024

/** Maximum size of the HTTP/1.1 handshake response we are willing to buffer. */
const MAX_HANDSHAKE_BYTES = 64 * 1024

/** Maximum number of bytes that may sit in the outbound queue. */
const MAX_OUTBOUND_BYTES = 64 * 1024 * 1024

/** Grace period before a half-closed socket is forcibly torn down. */
const CLOSE_GRACE_MS = 5_000

/** WebSocket frame opcodes (RFC 6455 §5.2). */
export const OPCODE_CONTINUATION = 0x0
export const OPCODE_TEXT = 0x1
export const OPCODE_BINARY = 0x2
export const OPCODE_CLOSE = 0x8
export const OPCODE_PING = 0x9
export const OPCODE_PONG = 0xa

/** Close status code used when the connection ended without a close frame. */
export const CLOSE_ABNORMAL = 1006

/** Close status code used when the peer violated the framing rules. */
export const CLOSE_PROTOCOL_ERROR = 1002

/** Close status code used when an inbound message exceeded the size limit. */
export const CLOSE_TOO_BIG = 1009

/** Configuration for {@link WebSocketClient}. */
export interface WebSocketOptions {
    /** Target URL; `wss://` uses TLS, `ws://` uses plain TCP. */
    url: string
    /** Extra HTTP headers sent with the Upgrade request. */
    headers?: Record<string, string>
    /** TLS options; `rejectUnauthorized` defaults to true. */
    tls?: import('node:tls').ConnectionOptions
    /** Handshake timeout in ms (default 20000). */
    handshakeTimeoutMs?: number
    /** Max incoming message size in bytes (default 16 MiB). */
    maxMessageBytes?: number
    /** Called with each complete binary message. */
    onMessage?: (data: Uint8Array) => void
    /** Called once the Upgrade handshake succeeded. */
    onOpen?: () => void
    /** Called exactly once when the connection is torn down. */
    onClose?: (code: number, reason: string) => void
    /** Called for every transport/protocol error. */
    onError?: (error: Error) => void
}

/**
 * A growable byte queue used to accumulate inbound socket data.
 *
 * Socket chunks arrive with arbitrary boundaries, so we copy them into one
 * contiguous buffer and let the frame parser consume from the front. The
 * buffer grows geometrically and the consumed prefix is reclaimed in place,
 * which keeps the amortised cost per byte at O(1).
 */
class ReceiveBuffer {
    private buf: Uint8Array
    /** Offset of the first unread byte. */
    private start = 0
    /** Offset one past the last valid byte. */
    private end = 0
    /** How far {@link indexOfHeaderTerminator} has already scanned. */
    private scanned = 0

    constructor(initialCapacity = 4096) {
        this.buf = new Uint8Array(initialCapacity)
    }

    /** Number of unread bytes. */
    get length(): number {
        return this.end - this.start
    }

    /** Appends `chunk` to the queue, growing the backing store if needed. */
    append(chunk: Uint8Array): void {
        if (chunk.length === 0) return
        if (this.end + chunk.length > this.buf.length && this.start > 0) {
            // Reclaim the consumed prefix before considering a reallocation.
            this.buf.copyWithin(0, this.start, this.end)
            this.end -= this.start
            this.start = 0
        }
        if (this.end + chunk.length > this.buf.length) {
            const size = this.end - this.start
            let capacity = this.buf.length > 0 ? this.buf.length * 2 : 4096
            while (capacity < size + chunk.length) capacity *= 2
            const grown = new Uint8Array(capacity)
            grown.set(this.buf.subarray(this.start, this.end))
            this.buf = grown
            this.start = 0
            this.end = size
        }
        this.buf.set(chunk, this.end)
        this.end += chunk.length
    }

    /** Reads the byte at `index` relative to the first unread byte. */
    byteAt(index: number): number {
        return this.buf[this.start + index]!
    }

    /** Reads a big-endian unsigned 16-bit integer at `index`. */
    uint16At(index: number): number {
        return (this.byteAt(index) << 8) | this.byteAt(index + 1)
    }

    /** Reads a big-endian unsigned 32-bit integer at `index`. */
    uint32At(index: number): number {
        return (
            (this.byteAt(index) * 0x1_00_00_00 +
                (this.byteAt(index + 1) << 16) +
                (this.byteAt(index + 2) << 8) +
                this.byteAt(index + 3)) >>>
            0
        )
    }

    /**
     * Reads a big-endian unsigned 64-bit integer at `index`.
     *
     * Values above `2^53 - 1` cannot be represented exactly and are rejected;
     * a frame that large is refused by the size limit anyway.
     */
    uint64At(index: number): number {
        const high = this.uint32At(index)
        const low = this.uint32At(index + 4)
        if (high > 0x1f_ffff) {
            throw new Error('frame payload length exceeds the safe integer range')
        }
        return high * 0x1_00_00_00_00 + low
    }

    /** Copies `length` bytes starting at `start` out of the queue. */
    slice(start: number, end: number): Uint8Array {
        return this.buf.slice(this.start + start, this.start + end)
    }

    /** Marks `count` bytes as consumed. */
    consume(count: number): void {
        this.start += count
        if (this.start >= this.end) {
            this.start = 0
            this.end = 0
        }
    }

    /** Drops every buffered byte. */
    clear(): void {
        this.start = 0
        this.end = 0
        this.scanned = 0
    }

    /**
     * Finds the index of the `\r\n\r\n` header terminator.
     *
     * The scan resumes from the previously inspected position so that a
     * response arriving in many chunks is not rescanned from the start.
     *
     * @returns The index of the first `\r`, or `-1` when not found yet.
     */
    indexOfHeaderTerminator(): number {
        const limit = this.end - this.start
        // A terminator may straddle the boundary of the previous scan.
        let i = Math.max(0, this.scanned - 3)
        for (; i + 3 < limit; i++) {
            if (
                this.buf[this.start + i] === 0x0d &&
                this.buf[this.start + i + 1] === 0x0a &&
                this.buf[this.start + i + 2] === 0x0d &&
                this.buf[this.start + i + 3] === 0x0a
            ) {
                return i
            }
        }
        this.scanned = limit
        return -1
    }
}

/**
 * A small RFC 6455 WebSocket client.
 *
 * ```ts
 * const ws = new WebSocketClient({
 *     url: 'wss://web.whatsapp.com/ws/chat',
 *     onMessage: (data) => console.log('got', data.length, 'bytes'),
 * })
 * await ws.connect()
 * ws.send(payload)
 * ```
 */
export class WebSocketClient {
    private readonly options: WebSocketOptions
    private readonly secure: boolean
    /** Host without IPv6 brackets, used for DNS and SNI. */
    private readonly host: string
    private readonly port: number
    /** Request target, e.g. `/ws/chat?x=1`. */
    private readonly requestTarget: string
    /** Value used for the `Host` header. */
    private readonly hostHeader: string
    private readonly maxMessageBytes: number
    private readonly handshakeTimeoutMs: number

    private state: 'connecting' | 'open' | 'closing' | 'closed' = 'connecting'
    private socket: Socket | undefined
    private started = false
    private finished = false
    private handshakeDone = false

    private connectPromise: Promise<void> | null = null
    private resolveConnect: (() => void) | null = null
    private rejectConnect: ((error: Error) => void) | null = null

    private handshakeTimer: NodeJS.Timeout | null = null
    private closeTimer: NodeJS.Timeout | null = null

    private closeCode: number | null = null
    private closeReason = ''

    private clientKey = ''
    private expectedAccept = ''

    private readonly handshakeRx = new ReceiveBuffer()
    private readonly rx = new ReceiveBuffer()

    /** Buffers of an in-flight fragmented message. */
    private readonly fragments: Uint8Array[] = []
    /** Total number of bytes buffered for the in-flight fragmented message. */
    private fragmentSize = 0

    /** Outbound frames waiting for the socket to drain. */
    private readonly outQueue: Uint8Array[] = []
    /** Index of the first queued frame. */
    private outHead = 0
    /** Number of bytes currently queued. */
    private outBytes = 0
    /** Whether a `'drain'` listener is already pending. */
    private drainPending = false

    /** Called with each complete binary message. */
    onMessage?: (data: Uint8Array) => void
    /** Called once the Upgrade handshake succeeded. */
    onOpen?: () => void
    /** Called exactly once when the connection is torn down. */
    onClose?: (code: number, reason: string) => void
    /** Called for every transport/protocol error. */
    onError?: (error: Error) => void

    constructor(options: WebSocketOptions) {
        this.options = options
        // The handlers may also be assigned after construction; the options
        // simply seed the initial values.
        this.onMessage = options.onMessage
        this.onOpen = options.onOpen
        this.onClose = options.onClose
        this.onError = options.onError
        const url = new URL(options.url)
        if (url.protocol !== 'wss:' && url.protocol !== 'ws:') {
            throw new Error(`WebSocketClient: unsupported URL scheme "${url.protocol}"`)
        }
        this.secure = url.protocol === 'wss:'
        const hostname = url.hostname
        // `URL.hostname` keeps the brackets around IPv6 literals; the socket
        // layer and SNI want the bare address.
        this.host = hostname.startsWith('[') && hostname.endsWith(']')
            ? hostname.slice(1, -1)
            : hostname
        this.port = url.port ? Number(url.port) : this.secure ? 443 : 80
        this.requestTarget = `${url.pathname || '/'}${url.search || ''}`
        const defaultPort = this.secure ? 443 : 80
        this.hostHeader =
            this.port === defaultPort ? hostname : `${hostname}:${this.port}`
        this.maxMessageBytes = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES
        this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS
    }

    /** `connecting` before the handshake, `open` afterwards, `closed` at the end. */
    get readyState(): 'connecting' | 'open' | 'closing' | 'closed' {
        return this.state
    }

    /**
     * Opens the connection; resolves once the HTTP 101 handshake completes.
     *
     * @throws The returned promise rejects with a descriptive error when the
     *   socket cannot be opened, the server does not answer with `101`, the
     *   handshake response is malformed, or the handshake times out.
     */
    connect(): Promise<void> {
        if (this.started) {
            return (
                this.connectPromise ??
                Promise.reject(new Error('WebSocketClient: connect() has already been called'))
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
     * Sends a binary message.
     *
     * @throws When the socket is not open.
     */
    send(data: Uint8Array): void {
        if (this.state !== 'open') {
            throw new Error(
                `WebSocketClient: cannot send, the socket is "${this.state}" instead of "open"`,
            )
        }
        this.writeFrame(OPCODE_BINARY, data)
    }

    /**
     * Sends a close frame and tears down the socket.
     *
     * @param code Close status code (default `1000`). Only `1000`-`1003` and
     *   the registered/private range `3000`-`4999` may be sent by a client.
     * @param reason Optional human readable reason.
     */
    close(code = 1000, reason = ''): void {
        if (this.state === 'closed' || this.state === 'closing') return
        if (!isValidCloseCode(code)) {
            throw new Error(`WebSocketClient: invalid close code ${code}`)
        }
        if (this.state === 'open') {
            try {
                this.writeFrame(OPCODE_CLOSE, buildClosePayload(code, reason))
            } catch {
                // The socket may already be gone; the teardown below still runs.
            }
        } else {
            this.failConnect(new Error('WebSocketClient: closed during the handshake'))
        }
        this.beginClosing(code, reason)
    }

    // ─── Connection setup ─────────────────────────────────────────────────────

    /** Creates the underlying socket and arms the handshake timeout. */
    private openSocket(): void {
        if (this.secure) {
            const socket = tlsConnect(this.buildTlsOptions())
            this.attachSocket(socket)
            socket.once('secureConnect', () => this.beginHandshake())
        } else {
            const socket = netConnect({ host: this.host, port: this.port })
            this.attachSocket(socket)
            socket.once('connect', () => this.beginHandshake())
        }
    }

    /** Builds the `node:tls` options for the connection. */
    private buildTlsOptions(): import('node:tls').ConnectionOptions {
        const options: import('node:tls').ConnectionOptions = {
            host: this.host,
            port: this.port,
            rejectUnauthorized: true,
            ...this.options.tls,
        }
        // SNI must carry a hostname; RFC 6066 forbids IP literals. Passing one
        // anyway makes Node emit a deprecation warning.
        if (isIP(this.host) === 0) {
            options.servername = this.host
        }
        // `exactOptionalPropertyTypes` is off, so an explicit `undefined` in
        // the user options would silently disable certificate validation.
        options.rejectUnauthorized = this.options.tls?.rejectUnauthorized ?? true
        return options
    }

    /** Wires the socket event handlers. */
    private attachSocket(socket: Socket): void {
        this.socket = socket
        socket.setNoDelay(true)
        socket.on('data', (chunk: Buffer) => this.handleData(chunk))
        socket.on('error', (error: Error) => this.handleSocketError(error))
        socket.on('close', () => this.handleSocketClose())
    }

    /** Sends the HTTP/1.1 Upgrade request and starts the handshake timer. */
    private beginHandshake(): void {
        if (this.finished) return
        this.clientKey = randomBytes(16).toString('base64')
        this.expectedAccept = createHash('sha1').update(this.clientKey + WS_GUID).digest('base64')

        const lines = [
            `GET ${this.requestTarget} HTTP/1.1`,
            `Host: ${this.hostHeader}`,
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Key: ${this.clientKey}`,
            'Sec-WebSocket-Version: 13',
        ]
        const extra = this.options.headers
        if (extra) {
            for (const name of Object.keys(extra)) {
                lines.push(`${name}: ${extra[name] ?? ''}`)
            }
        }
        const socket = this.socket
        if (!socket) return
        socket.write(`${lines.join('\r\n')}\r\n\r\n`)

        this.handshakeTimer = setTimeout(() => {
            this.handshakeTimer = null
            this.fail(
                new Error(
                    `WebSocketClient: handshake timed out after ${this.handshakeTimeoutMs}ms`,
                ),
            )
        }, this.handshakeTimeoutMs)
        // The timer must not keep the process alive on its own.
        this.handshakeTimer.unref()
    }

    // ─── Handshake response ───────────────────────────────────────────────────

    /** Handles inbound bytes; they belong to the handshake until it completes. */
    private handleData(chunk: Uint8Array): void {
        if (this.handshakeDone) {
            this.rx.append(chunk)
            this.parseFrames()
            return
        }
        this.handshakeRx.append(chunk)
        this.parseHandshake()
    }

    /** Attempts to complete the handshake from the buffered response bytes. */
    private parseHandshake(): void {
        const headerEnd = this.handshakeRx.indexOfHeaderTerminator()
        if (headerEnd < 0) {
            if (this.handshakeRx.length > MAX_HANDSHAKE_BYTES) {
                this.fail(new Error('WebSocketClient: the handshake response is too large'))
            }
            return
        }
        const headerText = decodeLatin1(this.handshakeRx.slice(0, headerEnd))
        const leftover = this.handshakeRx.slice(headerEnd + 4, this.handshakeRx.length)
        this.handshakeRx.clear()

        try {
            this.validateHandshake(headerText)
        } catch (error) {
            this.fail(toError(error))
            return
        }

        this.clearHandshakeTimer()
        this.handshakeDone = true
        this.state = 'open'
        const resolve = this.resolveConnect
        this.resolveConnect = null
        this.rejectConnect = null
        resolve?.()
        this.onOpen?.()

        if (leftover.length > 0) {
            this.rx.append(leftover)
            this.parseFrames()
        }
    }

    /** Validates the HTTP/1.1 101 response of the Upgrade handshake. */
    private validateHandshake(text: string): void {
        const lines = text.split('\r\n')
        const statusLine = lines[0] ?? ''
        const match = /^HTTP\/1\.1\s+(\d{3})(?:\s+(.*))?$/.exec(statusLine)
        if (!match) {
            throw new Error(
                `WebSocketClient: malformed handshake status line "${truncate(statusLine, 120)}"`,
            )
        }
        const status = Number(match[1])
        if (status !== 101) {
            throw new Error(
                `WebSocketClient: handshake failed with HTTP status ${status} (expected 101)`,
            )
        }

        const headers = new Map<string, string>()
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i]!
            const colon = line.indexOf(':')
            if (colon < 0) continue
            const name = line.slice(0, colon).trim().toLowerCase()
            const value = line.slice(colon + 1).trim()
            const previous = headers.get(name)
            headers.set(name, previous === undefined ? value : `${previous}, ${value}`)
        }

        const upgrade = headers.get('upgrade')
        if (upgrade?.toLowerCase() !== 'websocket') {
            throw new Error(
                `WebSocketClient: server did not upgrade to websocket (Upgrade: ${upgrade ?? '<missing>'})`,
            )
        }
        const connection = headers.get('connection')
        if (!connection || !connection.toLowerCase().includes('upgrade')) {
            throw new Error(
                `WebSocketClient: server did not accept the upgrade (Connection: ${connection ?? '<missing>'})`,
            )
        }
        const accept = headers.get('sec-websocket-accept')
        if (accept !== this.expectedAccept) {
            throw new Error(
                'WebSocketClient: server returned an invalid Sec-WebSocket-Accept value',
            )
        }
    }

    // ─── Frame parsing ────────────────────────────────────────────────────────

    /** Parses as many complete frames as the receive buffer holds. */
    private parseFrames(): void {
        for (;;) {
            const available = this.rx.length
            if (available < 2) return

            const first = this.rx.byteAt(0)
            const second = this.rx.byteAt(1)
            const fin = (first & 0x80) !== 0
            const reserved = first & 0x70
            const opcode = first & 0x0f
            const masked = (second & 0x80) !== 0
            let payloadLength = second & 0x7f
            let headerLength = 2

            if (payloadLength === 126) {
                if (available < 4) return
                payloadLength = this.rx.uint16At(2)
                headerLength = 4
            } else if (payloadLength === 127) {
                if (available < 10) return
                try {
                    payloadLength = this.rx.uint64At(2)
                } catch (error) {
                    this.fail(toError(error))
                    return
                }
                headerLength = 10
            }

            if (reserved !== 0) {
                this.protocolError('the reserved bits must be zero')
                return
            }
            if (masked) {
                this.protocolError('server frames must not be masked')
                return
            }
            if (opcode >= 0x8 && (!fin || payloadLength > 125)) {
                this.protocolError('control frames must not be fragmented and must be short')
                return
            }
            if (payloadLength > this.maxMessageBytes) {
                this.fail(
                    new Error(
                        `WebSocketClient: frame of ${payloadLength} bytes exceeds the ${this.maxMessageBytes} byte limit`,
                    ),
                    CLOSE_TOO_BIG,
                )
                return
            }
            if (available < headerLength + payloadLength) return

            const payload = this.rx.slice(headerLength, headerLength + payloadLength)
            this.rx.consume(headerLength + payloadLength)
            this.handleFrame(fin, opcode, payload)
            if (this.finished) return
        }
    }

    /** Dispatches a single complete frame. */
    private handleFrame(fin: boolean, opcode: number, payload: Uint8Array): void {
        switch (opcode) {
            case OPCODE_CLOSE:
                this.handleCloseFrame(payload)
                return
            case OPCODE_PING:
                this.safeWriteFrame(OPCODE_PONG, payload)
                return
            case OPCODE_PONG:
                return
            case OPCODE_TEXT:
            case OPCODE_BINARY:
                if (this.fragments.length > 0) {
                    this.protocolError('expected a continuation frame')
                    return
                }
                if (fin) {
                    this.deliver(payload)
                    return
                }
                this.fragments.length = 0
                this.fragments.push(payload)
                this.fragmentSize = payload.length
                return
            case OPCODE_CONTINUATION: {
                if (this.fragments.length === 0) {
                    this.protocolError('unexpected continuation frame')
                    return
                }
                this.fragmentSize += payload.length
                if (this.fragmentSize > this.maxMessageBytes) {
                    this.fail(
                        new Error(
                            `WebSocketClient: fragmented message exceeds the ${this.maxMessageBytes} byte limit`,
                        ),
                        CLOSE_TOO_BIG,
                    )
                    return
                }
                this.fragments.push(payload)
                if (fin) {
                    const chunks = this.fragments.slice()
                    this.fragments.length = 0
                    this.fragmentSize = 0
                    this.deliver(concatBytes(chunks))
                }
                return
            }
            default:
                this.protocolError(`unsupported opcode 0x${opcode.toString(16)}`)
        }
    }

    /** Hands a fully assembled message to the user callback. */
    private deliver(payload: Uint8Array): void {
        this.onMessage?.(payload)
    }

    /** Reacts to a close frame received from the peer. */
    private handleCloseFrame(payload: Uint8Array): void {
        let code = 1005
        let reason = ''
        if (payload.length >= 2) {
            code = (payload[0]! << 8) | payload[1]!
            reason = decodeUtf8(payload.subarray(2))
        }
        if (this.state === 'open') {
            try {
                this.writeFrame(OPCODE_CLOSE, payload.length >= 2 ? payload.subarray(0, 2) : EMPTY)
            } catch {
                // Nothing we can do if the socket already died.
            }
        }
        this.beginClosing(code, reason)
    }

    // ─── Frame writing ────────────────────────────────────────────────────────

    /**
     * Builds a masked client frame and queues it for transmission.
     *
     * @throws When the socket is not writable.
     */
    private writeFrame(opcode: number, payload: Uint8Array): void {
        const length = payload.length
        let headerLength: number
        if (length < 126) {
            headerLength = 2
        } else if (length < 0x1_00_00) {
            headerLength = 4
        } else {
            headerLength = 10
        }

        const frame = new Uint8Array(headerLength + 4 + length)
        frame[0] = 0x80 | opcode
        if (length < 126) {
            frame[1] = 0x80 | length
        } else if (length < 0x1_00_00) {
            frame[1] = 0x80 | 126
            frame[2] = (length >>> 8) & 0xff
            frame[3] = length & 0xff
        } else {
            frame[1] = 0x80 | 127
            const high = Math.floor(length / 0x1_00_00_00_00)
            const low = length - high * 0x1_00_00_00_00
            frame[2] = (high >>> 24) & 0xff
            frame[3] = (high >>> 16) & 0xff
            frame[4] = (high >>> 8) & 0xff
            frame[5] = high & 0xff
            frame[6] = (low >>> 24) & 0xff
            frame[7] = (low >>> 16) & 0xff
            frame[8] = (low >>> 8) & 0xff
            frame[9] = low & 0xff
        }

        const mask = randomBytes(4)
        frame.set(mask, headerLength)
        const base = headerLength + 4
        for (let i = 0; i < length; i++) {
            frame[base + i] = payload[i]! ^ mask[i & 3]!
        }

        if (this.outBytes + frame.length > MAX_OUTBOUND_BYTES) {
            throw new Error(
                `WebSocketClient: the outbound queue exceeded ${MAX_OUTBOUND_BYTES} bytes`,
            )
        }
        this.outBytes += frame.length
        this.outQueue.push(frame)
        this.flushOut()
    }

    /** Writes a frame but never throws (used for protocol level replies). */
    private safeWriteFrame(opcode: number, payload: Uint8Array): void {
        try {
            this.writeFrame(opcode, payload)
        } catch {
            // The connection is going away; ignore.
        }
    }

    /** Flushes queued frames while the socket accepts data. */
    private flushOut(): void {
        const socket = this.socket
        if (!socket || this.state === 'closed' || this.state === 'connecting') {
            this.outQueue.length = 0
            this.outHead = 0
            this.outBytes = 0
            return
        }
        while (this.outHead < this.outQueue.length) {
            const frame = this.outQueue[this.outHead]!
            this.outHead++
            this.outBytes -= frame.length
            const accepted = socket.write(frame)
            if (!accepted) {
                if (!this.drainPending) {
                    this.drainPending = true
                    socket.once('drain', () => {
                        this.drainPending = false
                        this.flushOut()
                    })
                }
                return
            }
        }
        this.outQueue.length = 0
        this.outHead = 0
        this.outBytes = 0
    }

    // ─── Teardown ─────────────────────────────────────────────────────────────

    /** Handles a socket level error. */
    private handleSocketError(error: Error): void {
        this.fail(error)
    }

    /** Handles the socket closing. */
    private handleSocketClose(): void {
        this.finish(this.closeCode ?? CLOSE_ABNORMAL, this.closeReason)
    }

    /**
     * Emits an error and tears the connection down.
     *
     * @param error The error to report.
     * @param code The close code reported to `onClose`.
     */
    private fail(error: Error, code = CLOSE_ABNORMAL): void {
        if (this.finished) return
        this.onError?.(error)
        this.failConnect(error)
        this.closeCode = code
        this.closeReason = error.message
        this.finish(code, error.message)
    }

    /** Reports a framing violation. */
    private protocolError(message: string): void {
        this.fail(new Error(`WebSocketClient: protocol error — ${message}`), CLOSE_PROTOCOL_ERROR)
    }

    /** Rejects the pending `connect()` promise, if any. */
    private failConnect(error: Error): void {
        const reject = this.rejectConnect
        this.rejectConnect = null
        this.resolveConnect = null
        reject?.(error)
    }

    /**
     * Starts the closing handshake: the close frame has already been queued,
     * so the socket is half-closed and torn down after a grace period.
     */
    private beginClosing(code: number, reason: string): void {
        if (this.state === 'closed' || this.state === 'closing') return
        const wasConnecting = this.state === 'connecting'
        this.state = 'closing'
        this.closeCode = code
        this.closeReason = reason
        const socket = this.socket
        if (!socket) {
            this.finish(code, reason)
            return
        }
        this.flushOut()
        if (wasConnecting) {
            // The socket is not connected yet; there is nothing to flush.
            socket.destroy()
            this.finish(code, reason)
            return
        }
        socket.end()
        this.closeTimer = setTimeout(() => {
            this.closeTimer = null
            this.finish(code, reason)
        }, CLOSE_GRACE_MS)
        this.closeTimer.unref()
    }

    /**
     * Destroys the socket and emits `onClose` exactly once.
     *
     * @param code The close status code.
     * @param reason The close reason.
     */
    private finish(code: number, reason: string): void {
        if (this.finished) return
        this.finished = true
        this.state = 'closed'
        this.clearHandshakeTimer()
        this.clearCloseTimer()
        this.outQueue.length = 0
        this.outHead = 0
        this.outBytes = 0
        this.fragments.length = 0
        const socket = this.socket
        this.socket = undefined
        if (socket) {
            socket.removeAllListeners()
            // A late socket error must not become an uncaught exception.
            socket.on('error', () => {})
            socket.destroy()
        }
        this.onClose?.(code, reason)
    }

    /** Clears the handshake timeout, if it is armed. */
    private clearHandshakeTimer(): void {
        if (!this.handshakeTimer) return
        clearTimeout(this.handshakeTimer)
        this.handshakeTimer = null
    }

    /** Clears the closing grace timer, if it is armed. */
    private clearCloseTimer(): void {
        if (!this.closeTimer) return
        clearTimeout(this.closeTimer)
        this.closeTimer = null
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/** An empty byte buffer. */
const EMPTY = new Uint8Array(0)

/** Concatenates `chunks` into a single freshly allocated buffer. */
function concatBytes(chunks: Uint8Array[]): Uint8Array {
    let total = 0
    for (const chunk of chunks) total += chunk.length
    const out = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
        out.set(chunk, offset)
        offset += chunk.length
    }
    return out
}

/** Builds the payload of a close frame (2-byte code plus UTF-8 reason). */
function buildClosePayload(code: number, reason: string): Uint8Array {
    const text = new TextEncoder().encode(reason)
    const payload = new Uint8Array(2 + text.length)
    payload[0] = (code >>> 8) & 0xff
    payload[1] = code & 0xff
    payload.set(text, 2)
    return payload
}

/** Decodes bytes as Latin-1 (a superset of ASCII) into a string. */
function decodeLatin1(bytes: Uint8Array): string {
    let out = ''
    for (let i = 0; i < bytes.length; i += 0x2000) {
        out += String.fromCharCode(...bytes.subarray(i, i + 0x2000))
    }
    return out
}

/** Decodes bytes as UTF-8 into a string. */
function decodeUtf8(bytes: Uint8Array): string {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

/** Normalises an unknown thrown value into an `Error`. */
function toError(value: unknown): Error {
    return value instanceof Error ? value : new Error(String(value))
}

/**
 * Checks whether `code` may be sent by an endpoint.
 *
 * RFC 6455 §7.4 reserves `1000`-`2999` for the protocol itself; a client
 * may only send `1000`-`1003` plus the registered/private `3000`-`4999`.
 */
function isValidCloseCode(code: number): boolean {
    if (!Number.isInteger(code)) return false
    if (code >= 3000 && code <= 4999) return true
    return code >= 1000 && code <= 1003
}

/** Shortens `value` to `limit` characters for error messages. */
function truncate(value: string, limit: number): string {
    return value.length > limit ? `${value.slice(0, limit)}…` : value
}
