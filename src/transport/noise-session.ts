/**
 * The Noise session driver for the WhatsApp Web transport.
 *
 * This module drives the handshake that {@link ../crypto/noise.ts} implements
 * at the primitive level, and wraps it in the protobuf framing WhatsApp
 * expects:
 *
 * ```text
 * client → server   HandshakeMessage{ clientHello: { ephemeral } }
 * server → client   HandshakeMessage{ serverHello: { ephemeral, static, payload } }
 * client → server   HandshakeMessage{ clientFinish: { static, payload } }
 * ```
 *
 * Two handshake modes exist:
 *
 * - **XX** (full): used for the first connection and whenever the server
 *   static key is unknown.
 * - **IK** (resume): used when the server static key was cached from a
 *   previous session. It is significantly cheaper (one round trip instead of
 *   two) but the server may reject it, in which case we transparently fall
 *   back to a full XX handshake using the *fallback* protocol name.
 */

import {
    concat,
    equalBytes,
    fromHex,
    generateX25519KeyPair,
    toSerializedPublicKey,
    type X25519KeyPair,
} from '../crypto/primitives.js'
import {
    NOISE_IK_NAME,
    NOISE_XX_FALLBACK_NAME,
    NOISE_XX_NAME,
    NoiseHandshake,
    NoiseTransport,
    sharedSecret,
    type NoiseSession,
} from '../crypto/noise.js'
import { decode, encode } from '../proto/codec.js'
import { FrameCodec, buildRoutingInfoPrefix } from './frame-codec.js'

/** A server hello message. */
export interface ServerHello {
    /** Server ephemeral public key. */
    ephemeral: Uint8Array
    /** Server static public key (encrypted). */
    static: Uint8Array
    /** Encrypted certificate payload. */
    payload: Uint8Array
}

/** Configuration for {@link NoiseSessionDriver}. */
export interface NoiseSessionConfig {
    /** Writes an encoded frame to the wire. */
    sendWire: (frame: Uint8Array) => void
    /** Long-term static key pair for this device. */
    clientStaticKeyPair: X25519KeyPair
    /** The plaintext payload encrypted into the handshake (login/registration). */
    payload: Uint8Array
    /** Cached server static key; enables the IK resume path. */
    serverStaticKey?: Uint8Array | null
    /** Optional routing info, prefixed to the intro frame (mobile transport). */
    routingInfo?: Uint8Array | null
    /** Noise prologue; defaults to the WA protocol header. */
    protocolHeader?: Uint8Array
    /** Verifies the server certificate chain when true. */
    verifyCertificateChain?: boolean
    /** Trusted root CA used for verification. */
    trustedRootCa?: { publicKey: Uint8Array; serial: number } | null
}

/** The result of a completed handshake. */
export interface NoiseHandshakeResult {
    /** The established transport session. */
    session: NoiseSession
    /** The server static key, to be cached for the next resume. */
    serverStaticKey: Uint8Array
    /** Which handshake mode was used. */
    mode: 'full' | 'resume'
}

/**
 * Drives the Noise handshake and the post-handshake frame flow.
 */
export class NoiseSessionDriver {
    private frameCodec: FrameCodec | null = null
    private transport: NoiseSession | null = null
    private readonly handshakeInbox: Uint8Array[] = []
    private handshakeWaiter: ((frame: Uint8Array) => void) | null = null
    private handshakeRejecter: ((error: Error) => void) | null = null
    private closedError: Error | null = null
    private readonly pendingDecryptedFrames: Uint8Array[] = []
    private serverStaticKey: Uint8Array | null = null

    /**
     * @param config Handshake configuration.
     */
    constructor(private readonly config: NoiseSessionConfig) {}

    /** The server static key observed during the handshake. */
    getServerStaticKey(): Uint8Array | null {
        return this.serverStaticKey
    }

    /**
     * Runs the handshake to completion.
     *
     * The caller must feed inbound wire bytes into {@link pushWireChunk};
     * the driver queues the handshake frames itself.
     */
    async start(): Promise<NoiseHandshakeResult> {
        const protocolHeader = this.config.protocolHeader ?? DEFAULT_PROTOCOL_HEADER
        const introFrame =
            this.config.routingInfo && this.config.routingInfo.length > 0
                ? concat(buildRoutingInfoPrefix(this.config.routingInfo), protocolHeader)
                : protocolHeader
        this.frameCodec = new FrameCodec(introFrame)

        const ephemeral = generateX25519KeyPair()
        const serverStatic = this.config.serverStaticKey

        if (serverStatic && serverStatic.length === 32) {
            const resumed = await this.tryResumeHandshake(serverStatic, ephemeral)
            if (resumed) {
                this.flushPendingFrames()
                return {
                    session: this.transport!,
                    serverStaticKey: this.serverStaticKey!,
                    mode: 'resume',
                }
            }
        }

        await this.fullHandshake(ephemeral)
        this.flushPendingFrames()
        return { session: this.transport!, serverStaticKey: this.serverStaticKey!, mode: 'full' }
    }

    /**
     * Waits for the next handshake frame.
     *
     * @param timeoutMs How long to wait for a frame.
     */
    private nextHandshakeFrame(timeoutMs = 10000): Promise<Uint8Array> {
        const queued = this.handshakeInbox.shift()
        if (queued) return Promise.resolve(queued)
        return new Promise<Uint8Array>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.handshakeWaiter = null
                this.handshakeRejecter = null
                reject(new Error(`noise handshake timed out after ${timeoutMs}ms`))
            }, timeoutMs)
            timer.unref?.()
            this.handshakeWaiter = (frame: Uint8Array): void => {
                clearTimeout(timer)
                this.handshakeWaiter = null
                this.handshakeRejecter = null
                resolve(frame)
            }
            this.handshakeRejecter = (error: Error): void => {
                clearTimeout(timer)
                this.handshakeWaiter = null
                this.handshakeRejecter = null
                reject(error)
            }
        })
    }

    /**
     * Encrypts and frames a payload for the wire.
     *
     * @param plaintext The payload to send.
     */
    encodeFrame(plaintext: Uint8Array): Uint8Array {
        if (!this.transport || !this.frameCodec) {
            throw new Error('noise: session is not established')
        }
        return this.frameCodec.encodeFrame(this.transport.encrypt(plaintext))
    }

    /**
     * Feeds wire bytes into the decoder and returns decrypted payloads.
     *
     * @param chunk Bytes received from the socket.
     */
    pushWireChunk(chunk: Uint8Array): Uint8Array[] {
        if (!this.frameCodec) return []
        const frames = this.frameCodec.pushWireChunk(chunk)
        if (!this.transport) {
            // Still handshaking: queue the raw frames for the handshake.
            for (const frame of frames) {
                const waiter = this.handshakeWaiter
                const rejecter = this.handshakeRejecter
                if (waiter && rejecter) {
                    this.handshakeWaiter = null
                    this.handshakeRejecter = null
                    waiter(frame)
                    continue
                }
                this.handshakeInbox.push(frame)
            }
            return []
        }
        const out: Uint8Array[] = []
        for (const frame of frames) {
            out.push(this.transport.decrypt(frame))
        }
        return out
    }

    /** Notifies the driver that the socket closed. */
    onSocketClosed(error?: Error): void {
        const closeError = error ?? new Error('noise: session socket closed')
        this.closedError = closeError
        const rejecter = this.handshakeRejecter
        if (rejecter) {
            this.handshakeRejecter = null
            this.handshakeWaiter = null
            rejecter(closeError)
        }
    }

    /** Moves buffered post-handshake frames to the pending queue. */
    private flushPendingFrames(): void {
        if (!this.transport || this.handshakeInbox.length === 0) return
        for (const frame of this.handshakeInbox) {
            this.pendingDecryptedFrames.push(this.transport.decrypt(frame))
        }
        this.handshakeInbox.length = 0
    }

    /**
     * Runs the full XX handshake.
     */
    private async fullHandshake(ephemeral: X25519KeyPair): Promise<void> {
        const handshake = new NoiseHandshake()
        handshake.start(NOISE_XX_NAME, this.config.protocolHeader ?? DEFAULT_PROTOCOL_HEADER)
        handshake.authenticate(ephemeral.publicKey)

        const clientHello = encode('HandshakeMessage', {
            clientHello: { ephemeral: ephemeral.publicKey },
        })
        const serverHelloFrame = await this.sendAndReceive(clientHello)
        await this.continueFullHandshake(handshake, serverHelloFrame, ephemeral)
    }

    /**
     * Continues a full handshake from the server hello.
     */
    private async continueFullHandshake(
        handshake: NoiseHandshake,
        serverHelloFrame: Uint8Array,
        ephemeral: X25519KeyPair,
    ): Promise<void> {
        const serverHello = parseServerHello(serverHelloFrame)
        const serverEphemeral = serverHello.ephemeral
        handshake.authenticate(serverEphemeral)
        handshake.mixIntoKey(sharedSecret(ephemeral.privateKey, serverEphemeral))
        const serverStatic = handshake.decrypt(serverHello.static)
        handshake.mixIntoKey(sharedSecret(ephemeral.privateKey, serverStatic))
        const certificate = handshake.decrypt(serverHello.payload)

        if (this.config.verifyCertificateChain !== false) {
            await verifyCertificateChain(
                certificate,
                serverStatic,
                this.config.trustedRootCa ?? getProductionRootCa(),
            )
        }
        this.serverStaticKey = serverStatic

        const encryptedClientStatic = handshake.encrypt(this.config.clientStaticKeyPair.publicKey)
        handshake.mixIntoKey(
            sharedSecret(this.config.clientStaticKeyPair.privateKey, serverEphemeral),
        )
        const encryptedPayload = handshake.encrypt(this.config.payload)
        const clientFinish = encode('HandshakeMessage', {
            clientFinish: { static: encryptedClientStatic, payload: encryptedPayload },
        })
        this.sendFrame(clientFinish)

        this.transport = handshake.finish()
    }

    /**
     * Attempts an IK (resume) handshake.
     *
     * @returns `null` when the server asked for a full handshake instead.
     */
    private async tryResumeHandshake(
        serverStatic: Uint8Array,
        ephemeral: X25519KeyPair,
    ): Promise<boolean> {
        const handshake = new NoiseHandshake()
        handshake.start(NOISE_IK_NAME, this.config.protocolHeader ?? DEFAULT_PROTOCOL_HEADER)
        handshake.authenticate(serverStatic)
        handshake.authenticate(ephemeral.publicKey)

        const agreement1 = sharedSecret(ephemeral.privateKey, serverStatic)
        const agreement2 = sharedSecret(this.config.clientStaticKeyPair.privateKey, serverStatic)
        handshake.mixIntoKey(agreement1)
        const encryptedClientStatic = handshake.encrypt(this.config.clientStaticKeyPair.publicKey)
        handshake.mixIntoKey(agreement2)
        const encryptedPayload = handshake.encrypt(this.config.payload)

        const clientHello = encode('HandshakeMessage', {
            clientHello: {
                ephemeral: ephemeral.publicKey,
                payload: encryptedPayload,
                static: encryptedClientStatic,
            },
        })
        const serverHelloFrame = await this.sendAndReceive(clientHello)

        let serverHello: ServerHello
        try {
            serverHello = parseServerHello(serverHelloFrame)
        } catch {
            // The server did not answer with a usable hello: fall back.
            return false
        }
        if (serverHello.static.length === 0) {
            // The server wants a full handshake; retry with the fallback name.
            await this.resumeFallbackHandshake(ephemeral, serverHelloFrame)
            return true
        }
        if (serverHello.ephemeral.length === 0 || serverHello.payload.length === 0) {
            throw new Error('noise: resume handshake is missing server hello fields')
        }

        const serverEphemeral = serverHello.ephemeral
        handshake.authenticate(serverEphemeral)
        handshake.mixIntoKey(sharedSecret(ephemeral.privateKey, serverEphemeral))
        handshake.mixIntoKey(
            sharedSecret(this.config.clientStaticKeyPair.privateKey, serverEphemeral),
        )
        handshake.decrypt(serverHello.payload)
        this.serverStaticKey = serverStatic
        this.transport = handshake.finish()
        return true
    }

    /**
     * Completes a full handshake after the server rejected the IK resume.
     */
    private async resumeFallbackHandshake(
        ephemeral: X25519KeyPair,
        serverHelloFrame: Uint8Array,
    ): Promise<void> {
        const fallback = new NoiseHandshake()
        fallback.start(
            NOISE_XX_FALLBACK_NAME,
            this.config.protocolHeader ?? DEFAULT_PROTOCOL_HEADER,
        )
        fallback.authenticate(ephemeral.publicKey)
        await this.continueFullHandshake(fallback, serverHelloFrame, ephemeral)
    }

    /** Sends a handshake frame. */
    private sendFrame(frame: Uint8Array): void {
        if (!this.frameCodec) {
            throw new Error('noise: frame codec is not initialised')
        }
        this.config.sendWire(this.frameCodec.encodeFrame(frame))
    }

    /** Sends a handshake frame and waits for the reply. */
    private async sendAndReceive(frame: Uint8Array): Promise<Uint8Array> {
        this.sendFrame(frame)
        return this.nextHandshakeFrame()
    }
}

/** The default Noise prologue. */
const DEFAULT_PROTOCOL_HEADER = new Uint8Array([0x57, 0x41, 0x06, 0x03])

/**
 * Returns the production WhatsApp root certificate authority.
 *
 * Computed lazily so module load never touches the crypto helpers.
 */
export function getProductionRootCa(): { publicKey: Uint8Array; serial: number } {
    return {
        publicKey: fromHex('142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b'),
        serial: 0,
    }
}

/**
 * Extracts the server hello from a handshake frame.
 *
 * @param frame The raw handshake frame.
 */
export function parseServerHello(frame: Uint8Array): ServerHello {
    const parsed = decode('HandshakeMessage', frame)
    const hello = parsed.serverHello as Record<string, unknown> | undefined
    if (!hello) {
        throw new Error('noise: handshake frame is missing serverHello')
    }
    return {
        ephemeral: (hello.ephemeral as Uint8Array) ?? new Uint8Array(0),
        static: (hello.static as Uint8Array) ?? new Uint8Array(0),
        payload: (hello.payload as Uint8Array) ?? new Uint8Array(0),
    }
}

/**
 * Verifies the WhatsApp noise certificate chain.
 *
 * The chain has two levels: an intermediate certificate signed by the
 * production root CA, and a leaf certificate signed by the intermediate
 * whose key must equal the server's static key.
 *
 * @param certificateChain The decrypted certificate chain bytes.
 * @param serverStatic The server static key observed in the handshake.
 * @param rootCa The trusted root certificate authority.
 */
export async function verifyCertificateChain(
    certificateChain: Uint8Array,
    serverStatic: Uint8Array,
    rootCa: { publicKey: Uint8Array; serial: number },
): Promise<void> {
    const { xeddsaVerify } = await import('../crypto/curve25519.js')
    const chain = decode('CertChain', certificateChain)
    const leaf = chain.leaf as Record<string, unknown> | undefined
    const intermediate = chain.intermediate as Record<string, unknown> | undefined
    if (!leaf || !intermediate) {
        throw new Error('noise: certificate chain is missing leaf/intermediate')
    }

    const intermediateParsed = parseCertificate(intermediate)
    if (intermediateParsed.issuerSerial !== rootCa.serial) {
        throw new Error('noise: intermediate certificate issuer mismatch')
    }
    if (!xeddsaVerify(rootCa.publicKey, intermediateParsed.details, intermediateParsed.signature)) {
        throw new Error('noise: intermediate certificate signature is invalid')
    }

    const leafParsed = parseCertificate(leaf)
    if (leafParsed.issuerSerial !== intermediateParsed.serial) {
        throw new Error('noise: leaf certificate issuer mismatch')
    }
    if (!xeddsaVerify(intermediateParsed.key, leafParsed.details, leafParsed.signature)) {
        throw new Error('noise: leaf certificate signature is invalid')
    }
    if (!equalBytes(leafParsed.key, serverStatic)) {
        throw new Error('noise: leaf certificate key mismatch with server static key')
    }
}

/** A parsed noise certificate. */
interface ParsedCertificate {
    serial: number
    issuerSerial: number
    key: Uint8Array
    details: Uint8Array
    signature: Uint8Array
}

/** Parses a `NoiseCertificate` value. */
function parseCertificate(value: Record<string, unknown>): ParsedCertificate {
    const details = value.details as Uint8Array
    const signature = value.signature as Uint8Array
    if (!details || !signature) {
        throw new Error('noise: certificate is missing details/signature')
    }
    if (signature.length !== 64) {
        throw new Error(`noise: invalid certificate signature size ${signature.length}`)
    }
    const parsed = decode('CertChain_NoiseCertificate_Details', details)
    return {
        serial: parsed.serial as number,
        issuerSerial: parsed.issuerSerial as number,
        key: parsed.key as Uint8Array,
        details,
        signature,
    }
}

/** Re-exported so callers do not need to import the crypto module directly. */
export { toSerializedPublicKey }
export type { NoiseTransport }
