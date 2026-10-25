/**
 * The WhatsApp *mobile* (WAP) transport.
 *
 * The native WhatsApp apps do not use WebSocket: they open a plain TCP
 * connection to `g.whatsapp.net:443` and exchange the very same binary node
 * protocol that WhatsApp Web uses, framed with a 3-byte big-endian length
 * and encrypted with Noise.
 *
 * ```text
 *   node → encodeBinaryNodeStanza → Noise.encrypt → length prefix → TCP
 *   TCP → length prefix → Noise.decrypt → decodeBinaryNodeStanza → node
 * ```
 *
 * The only mobile-specific detail is the *routing info*: after a successful
 * registration the server hands out a routing blob that has to be attached
 * to the very first frame of every subsequent connection, so the server can
 * route the client to the right edge.
 */

import { Connection } from './connection.js'
import type { BinaryNode } from './binary/types.js'
import type { NoiseSessionConfig } from './noise-session.js'
import { TcpSocket } from './tcp.js'
import type { TransportHandlers } from './types.js'

/** The default WhatsApp mobile endpoint. */
export const DEFAULT_MOBILE_TCP_URL = 'tcp://g.whatsapp.net:443'

/** The default WhatsApp mobile host. */
export const DEFAULT_MOBILE_HOST = 'g.whatsapp.net'

/** The default WhatsApp mobile port. */
export const DEFAULT_MOBILE_PORT = 443

/** Configuration for the mobile transport. */
export interface MobileTransportConfig {
    /** The host to connect to. */
    host?: string
    /** The port to connect to. */
    port?: number
    /** The Noise handshake configuration. */
    noise: Omit<NoiseSessionConfig, 'sendWire'>
    /** Handshake timeout in milliseconds. */
    handshakeTimeoutMs?: number
    /** Socket connect timeout in milliseconds. */
    connectTimeoutMs?: number
    /** Event handlers. */
    handlers?: TransportHandlers
}

/**
 * A WhatsApp mobile (WAP) connection.
 */
export class MobileTransport {
    private readonly socket: TcpSocket
    private readonly connection: Connection
    private readonly handlers: TransportHandlers
    private closed = false

    /**
     * @param config The transport configuration.
     */
    constructor(private readonly config: MobileTransportConfig) {
        this.handlers = config.handlers ?? {}

        this.socket = new TcpSocket({
            host: config.host ?? DEFAULT_MOBILE_HOST,
            port: config.port ?? DEFAULT_MOBILE_PORT,
            ...(config.connectTimeoutMs !== undefined
                ? { connectTimeoutMs: config.connectTimeoutMs }
                : {}),
            onData: (chunk) => {
                this.connection.handleData(chunk)
            },
            onClose: (error) => {
                this.closed = true
                this.connection.handleClose(error ?? new Error('tcp socket closed'))
            },
            onError: (error) => {
                this.handlers.onError?.(error)
            },
        })

        this.connection = new Connection({
            noise: config.noise,
            sendWire: (frame) => {
                this.socket.write(frame)
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
