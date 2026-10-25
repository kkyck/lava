/**
 * The WhatsApp *Web* transport.
 *
 * The web transport speaks the same binary node protocol as the mobile
 * transport, but carries it inside a WebSocket:
 *
 * ```text
 *   node → encodeBinaryNodeStanza → Noise.encrypt → length prefix → WebSocket
 *   WebSocket → length prefix → Noise.decrypt → decodeBinaryNodeStanza → node
 * ```
 *
 * The Noise handshake is identical to the mobile one; only the socket and
 * the framing differ.
 */

import { Connection } from './connection.js'
import type { BinaryNode } from './binary/types.js'
import type { NoiseSessionConfig } from './noise-session.js'
import type { TransportHandlers } from './types.js'
import { WebSocketClient } from './websocket.js'

/** The default WhatsApp Web socket endpoint. */
export const DEFAULT_WEB_SOCKET_URL = 'wss://web.whatsapp.com/ws/chat'

/** Configuration for the web transport. */
export interface WebTransportConfig {
    /** The WebSocket URL, e.g. `wss://web.whatsapp.com/ws/chat`. */
    url?: string
    /** The Noise handshake configuration. */
    noise: Omit<NoiseSessionConfig, 'sendWire'>
    /** Handshake timeout in milliseconds. */
    handshakeTimeoutMs?: number
    /** Socket connect timeout in milliseconds. */
    connectTimeoutMs?: number
    /** Extra HTTP headers for the Upgrade request. */
    headers?: Record<string, string>
    /** Event handlers. */
    handlers?: TransportHandlers
}

/**
 * A WhatsApp Web connection.
 */
export class WebTransport {
    private readonly socket: WebSocketClient
    private readonly connection: Connection
    private readonly handlers: TransportHandlers
    private closed = false

    /**
     * @param config The transport configuration.
     */
    constructor(private readonly config: WebTransportConfig) {
        this.handlers = config.handlers ?? {}

        this.socket = new WebSocketClient({
            url: config.url ?? DEFAULT_WEB_SOCKET_URL,
            ...(config.headers ? { headers: config.headers } : {}),
            ...(config.connectTimeoutMs !== undefined
                ? { handshakeTimeoutMs: config.connectTimeoutMs }
                : {}),
            onMessage: (data) => {
                this.connection.handleData(data)
            },
            onClose: (code, reason) => {
                this.closed = true
                this.connection.handleClose(
                    new Error(`websocket closed (${code}${reason ? `: ${reason}` : ''})`),
                )
            },
            onError: (error) => {
                this.handlers.onError?.(error)
            },
        })

        this.connection = new Connection({
            noise: config.noise,
            sendWire: (frame) => {
                this.socket.send(frame)
            },
            closeWire: () => {
                this.socket.close()
            },
            ...(config.handshakeTimeoutMs !== undefined
                ? { handshakeTimeoutMs: config.handshakeTimeoutMs }
                : {}),
            handlers: {
                onNode: (node) => {
                    this.handlers.onNode?.(node)
                },
                onClose: (error) => {
                    this.closed = true
                    this.handlers.onClose?.(error)
                },
                onError: (error) => {
                    this.handlers.onError?.(error)
                },
            },
        })
    }

    /**
     * Opens the socket and runs the Noise handshake.
     */
    async start(): Promise<void> {
        await this.socket.connect()
        await this.connection.start(this.config.handshakeTimeoutMs ?? 10000)
    }

    /**
     * Sends a node to the server.
     *
     * @param node The node to send.
     */
    send(node: BinaryNode): void {
        this.connection.send(node)
    }

    /**
     * Sends an IQ stanza and waits for the matching response.
     *
     * @param node The IQ node.
     * @param timeoutMs Response timeout.
     */
    async query(node: BinaryNode, timeoutMs = 15000): Promise<BinaryNode> {
        return this.connection.query(node, timeoutMs)
    }

    /** The cached server static key, usable for an IK resume. */
    getServerStaticKey(): Uint8Array | null {
        return this.connection.getServerStaticKey()
    }

    /** Whether the transport has been closed. */
    get isClosed(): boolean {
        return this.closed
    }

    /** Closes the transport. */
    close(): void {
        this.closed = true
        this.connection.close()
    }
}
