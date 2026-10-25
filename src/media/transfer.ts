/**
 * Media transfer: talking to the WhatsApp CDN.
 *
 * Uploading a media file is a three-step dance:
 *
 * 1. The client asks the server for a *media connection* — an `<iq
 *    type="set" xmlns="w:m"><media_conn/></iq>` that answers with an upload
 *    token and a list of CDN hosts.
 * 2. The file is encrypted with a fresh media key (see `./crypto.ts`) and
 *    `POST`ed to the CDN. The upload URL carries the token and the hash of
 *    the encrypted bytes, so the CDN can verify what it received.
 * 3. The CDN answers with the `url` and the `direct_path` that go into the
 *    message stanza.
 *
 * Downloading is the mirror image: the CDN is asked for the encrypted bytes
 * and the client decrypts and verifies them locally.
 */

import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'

import { WA_IQ_TYPES, WA_NODE_TAGS, WA_XMLNS } from '../protocol/constants.js'
import { HOST_DOMAIN } from '../protocol/jid.js'
import { buildIqNode } from '../transport/node/query.js'
import {
    findNodeChild,
    getNodeChildrenByTag,
} from '../transport/node/helpers.js'
import type { BinaryNode } from '../transport/binary/types.js'
import { base64UrlEncode } from '../util/base64.js'
import { randomBytesOf } from '../crypto/primitives.js'
import type { WaMediaType } from '../protocol/media.js'
import type { MediaPayload } from '../protocol/media.js'
import {
    decryptMedia,
    encryptMedia,
    MEDIA_KEY_LENGTH,
} from './crypto.js'

/** The CDN hosts used when the server does not name any. */
export const DEFAULT_MEDIA_HOSTS: readonly string[] = Object.freeze([
    'mmg.whatsapp.net',
    'mmg-fallback.whatsapp.net',
])

/** The upload paths of the WhatsApp CDN, per media kind. */
export const MEDIA_UPLOAD_PATHS: Readonly<Record<string, string>> = Object.freeze({
    image: '/mms/image',
    video: '/mms/video',
    audio: '/mms/audio',
    document: '/mms/document',
    sticker: '/mms/sticker',
    gif: '/mms/gif',
    ptt: '/mms/ptt',
})

/** The default timeout of a media transfer, in milliseconds. */
export const MEDIA_TIMEOUT_MS = 60_000

/** The media kinds the library can upload. */
export type { WaMediaType } from '../protocol/media.js'

/** A media connection: the upload token and the CDN hosts. */
export interface WaMediaConn {
    /** The upload token. */
    auth: string
    /** When the connection expires, in milliseconds since the epoch. */
    expiresAtMs: number
    /** The CDN hosts. */
    hosts: { hostname: string; isFallback: boolean }[]
}

/**
 * Builds the IQ that asks the server for a media connection.
 */
export function buildMediaConnIq(): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, HOST_DOMAIN, WA_XMLNS.MEDIA, [
        { tag: WA_NODE_TAGS.MEDIA_CONN, attrs: {} },
    ])
}

/**
 * Parses the media connection the server answers with.
 *
 * @param node The `<iq>` response.
 * @param nowMs The current time, used to compute the expiry.
 */
export function parseMediaConnResponse(node: BinaryNode, nowMs = Date.now()): WaMediaConn {
    const connNode = findNodeChild(node, WA_NODE_TAGS.MEDIA_CONN)
    if (!connNode) throw new Error('media_conn response is missing media_conn node')

    const auth = connNode.attrs.auth
    if (!auth) throw new Error('media_conn response is missing auth')

    const ttl = Number.parseInt(connNode.attrs.ttl ?? '', 10)
    if (!Number.isSafeInteger(ttl) || ttl <= 0) {
        throw new Error('media_conn response has an invalid ttl')
    }
    const expiresAtMs = ttl >= 1_000_000_000 ? ttl * 1000 : nowMs + ttl * 1000

    const hosts: { hostname: string; isFallback: boolean }[] = []
    for (const host of getNodeChildrenByTag(connNode, WA_NODE_TAGS.HOST)) {
        const hostname = host.attrs.hostname
        if (hostname) hosts.push({ hostname, isFallback: host.attrs.type === 'fallback' })
    }
    if (hosts.length === 0) throw new Error('media_conn response contains no hosts')

    return { auth, expiresAtMs, hosts }
}

/**
 * Picks the host an upload should go to.
 *
 * The primary host is preferred; the fallback hosts are only used when the
 * primary one fails.
 *
 * @param conn The media connection.
 */
export function selectMediaHost(conn: WaMediaConn): string {
    const primary = conn.hosts.find((host) => !host.isFallback)
    return primary?.hostname ?? conn.hosts[0]!.hostname
}

/**
 * Builds the URL an encrypted media file is uploaded to.
 *
 * @param host The CDN host.
 * @param path The upload path (`/mms/image`, …).
 * @param auth The upload token.
 * @param fileEncSha256 The SHA-256 of the encrypted payload.
 */
export function buildMediaUploadUrl(
    host: string,
    path: string,
    auth: string,
    fileEncSha256: Uint8Array,
): string {
    const token = base64UrlEncode(fileEncSha256)
    return (
        `https://${host}${path}/${token}` +
        `?auth=${encodeURIComponent(auth)}&token=${encodeURIComponent(token)}`
    )
}

/** An HTTP request against the CDN. */
export interface MediaHttpRequest {
    /** The URL to fetch. */
    url: string
    /** The HTTP method. */
    method: 'GET' | 'POST'
    /** The request headers. */
    headers: Record<string, string>
    /** The request body, for uploads. */
    body?: Uint8Array
    /** The timeout, in milliseconds. */
    timeoutMs: number
    /** An optional abort signal. */
    signal?: AbortSignal
}

/** The response of a media HTTP request. */
export interface MediaHttpResponse {
    /** The HTTP status code. */
    status: number
    /** The response headers. */
    headers: Record<string, string>
    /** The response body. */
    body: Uint8Array
}

/** Performs a media HTTP request. */
export type MediaHttpHandler = (request: MediaHttpRequest) => Promise<MediaHttpResponse>

/**
 * The default HTTP handler, built on Node's `http`/`https` modules.
 */
export const defaultMediaHttpHandler: MediaHttpHandler = async (request) => {
    const url = new URL(request.url)
    const send = url.protocol === 'http:' ? httpRequest : httpsRequest

    return new Promise<MediaHttpResponse>((resolve, reject) => {
        const req = send(
            url,
            {
                method: request.method,
                headers: request.headers,
                signal: request.signal,
            },
            (res) => {
                const chunks: Uint8Array[] = []
                res.on('data', (chunk: Buffer) => chunks.push(new Uint8Array(chunk)))
                res.on('error', reject)
                res.on('end', () => {
                    const headers: Record<string, string> = {}
                    for (const [key, value] of Object.entries(res.headers)) {
                        if (typeof value === 'string') headers[key] = value
                        else if (Array.isArray(value)) headers[key] = value.join(', ')
                    }
                    let length = 0
                    for (const chunk of chunks) length += chunk.length
                    const body = new Uint8Array(length)
                    let offset = 0
                    for (const chunk of chunks) {
                        body.set(chunk, offset)
                        offset += chunk.length
                    }
                    resolve({ status: res.statusCode ?? 500, headers, body })
                })
            },
        )

        const timer = setTimeout(() => {
            req.destroy(new Error(`media request timed out after ${request.timeoutMs}ms`))
        }, request.timeoutMs)
        timer.unref?.()

        req.on('error', (error) => {
            clearTimeout(timer)
            reject(error)
        })
        req.on('close', () => clearTimeout(timer))

        if (request.body) req.end(request.body)
        else req.end()
    })
}

/** The options of a media transfer. */
export interface MediaTransferOptions {
    /** Runs an IQ against the server. */
    query: (node: BinaryNode, timeoutMs?: number) => Promise<BinaryNode>
    /** The HTTP handler; the default one talks to the real CDN. */
    http?: MediaHttpHandler
    /** The timeout of a transfer, in milliseconds. */
    timeoutMs?: number
    /** The CDN hosts used when the server names none. */
    hosts?: readonly string[]
    /** A media connection to reuse instead of fetching a new one. */
    conn?: WaMediaConn
}

/** The result of a media upload. */
export interface WaMediaUpload {
    /** The CDN URL of the uploaded file. */
    url: string
    /** The path the CDN serves the file under. */
    directPath: string
    /** The media key the file was encrypted with. */
    mediaKey: Uint8Array
    /** The SHA-256 of the plaintext. */
    fileSha256: Uint8Array
    /** The SHA-256 of the encrypted payload. */
    fileEncSha256: Uint8Array
    /** The length of the plaintext. */
    fileLength: number
    /** The timestamp the media key was created at, in seconds. */
    mediaKeyTimestamp: number
}

/** The media payload of a message. */
export type { MediaPayload as WaMediaPayload } from '../protocol/media.js'

/**
 * Fetches a media connection, caching it until it expires.
 */
export class MediaConnectionCache {
    private conn: WaMediaConn | null = null

    /**
     * Returns the current media connection, fetching a new one when the
     * cached one expired.
     *
     * @param options The transfer options.
     */
    async get(options: MediaTransferOptions): Promise<WaMediaConn> {
        const cached = this.conn
        if (cached && Date.now() + 30_000 < cached.expiresAtMs) return cached
        const response = await options.query(buildMediaConnIq(), options.timeoutMs)
        const conn = parseMediaConnResponse(response)
        this.conn = conn
        return conn
    }

    /** Forgets the cached media connection. */
    clear(): void {
        this.conn = null
    }
}

/**
 * Encrypts a media file and uploads it to the WhatsApp CDN.
 *
 * @param options The transfer options.
 * @param input The file to upload.
 */
export async function uploadMedia(
    options: MediaTransferOptions,
    input: {
        /** The media bytes. */
        data: Uint8Array
        /** The media kind. */
        type: WaMediaType
        /** The MIME type of the file. */
        mimetype: string
        /** The media key; a fresh one is generated when omitted. */
        mediaKey?: Uint8Array
        /** An optional abort signal. */
        signal?: AbortSignal
    },
): Promise<WaMediaUpload> {
    const mediaKey = input.mediaKey ?? randomBytesOf(MEDIA_KEY_LENGTH)

    const encrypted = encryptMedia(input.type, mediaKey, input.data)
    const conn = options.conn ?? (await new MediaConnectionCache().get(options))
    const host = selectMediaHost(conn)
    const path = MEDIA_UPLOAD_PATHS[input.type]
    if (!path) throw new Error(`unsupported media type: ${input.type}`)

    const url = buildMediaUploadUrl(host, path, conn.auth, encrypted.fileEncSha256)
    const http = options.http ?? defaultMediaHttpHandler
    const response = await http({
        url,
        method: 'POST',
        headers: {
            'content-type': input.mimetype,
            'content-length': String(encrypted.ciphertextHmac.length),
        },
        body: encrypted.ciphertextHmac,
        timeoutMs: options.timeoutMs ?? MEDIA_TIMEOUT_MS,
        ...(input.signal ? { signal: input.signal } : {}),
    })

    if (response.status < 200 || response.status >= 300) {
        throw new Error(`media upload failed with status ${response.status}`)
    }

    let parsed: { url?: string; direct_path?: string }
    try {
        parsed = JSON.parse(new TextDecoder().decode(response.body)) as {
            url?: string
            direct_path?: string
        }
    } catch (error) {
        throw new Error(
            `media upload returned invalid json: ${
                error instanceof Error ? error.message : String(error)
            }`,
        )
    }
    if (!parsed.url || !parsed.direct_path) {
        throw new Error('media upload response is missing url/direct_path')
    }

    return {
        url: parsed.url,
        directPath: parsed.direct_path,
        mediaKey,
        fileSha256: encrypted.fileSha256,
        fileEncSha256: encrypted.fileEncSha256,
        fileLength: encrypted.plaintextLength,
        mediaKeyTimestamp: Math.floor(Date.now() / 1000),
    }
}

/**
 * Downloads an encrypted media file and decrypts it.
 *
 * @param options The transfer options.
 * @param payload The media payload of the message.
 */
export async function downloadMedia(
    options: MediaTransferOptions,
    payload: MediaPayload,
): Promise<Uint8Array> {
    const hosts = options.hosts ?? DEFAULT_MEDIA_HOSTS
    const path = payload.directPath.startsWith('/')
        ? payload.directPath
        : `/${payload.directPath}`
    const http = options.http ?? defaultMediaHttpHandler

    let lastError: unknown = null
    for (const host of hosts) {
        try {
            const response = await http({
                url: `https://${host}${path}`,
                method: 'GET',
                headers: {},
                timeoutMs: options.timeoutMs ?? MEDIA_TIMEOUT_MS,
            })
            if (response.status < 200 || response.status >= 300) {
                throw new Error(`media download failed with status ${response.status}`)
            }
            return decryptMedia(
                payload.mediaType,
                payload.mediaKey,
                response.body,
                payload.fileSha256,
                payload.fileEncSha256,
            ).plaintext
        } catch (error) {
            lastError = error
        }
    }
    throw lastError instanceof Error ? lastError : new Error('media download failed')
}
