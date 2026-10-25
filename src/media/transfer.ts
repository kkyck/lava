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
import { base64UrlEncodePadded } from '../util/base64.js'
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

/** A CDN host the server named in a media connection. */
export interface WaMediaHost {
    /** The host name. */
    hostname: string
    /** Whether the host is the designated fallback. */
    isFallback: boolean
    /**
     * The media types the host accepts for uploads.
     *
     * `undefined` means the host did not say, which the official client reads
     * as "every media type".
     */
    uploadable?: string[]
    /**
     * The media types the host serves for downloads.
     *
     * `undefined` means the host did not say, which the official client reads
     * as "every media type".
     */
    downloadable?: string[]
    /** The fallback host nested inside this one, when the server named one. */
    fallback?: string
}

/** A media connection: the upload token and the CDN hosts. */
export interface WaMediaConn {
    /** The upload token. */
    auth: string
    /** When the host routes expire, in milliseconds since the epoch. */
    expiresAtMs: number
    /** When the upload token expires, in milliseconds since the epoch. */
    authExpiresAtMs: number
    /** The lifetime of the upload token, in seconds. */
    authTtlSeconds: number
    /** When the connection was requested, in milliseconds since the epoch. */
    queriedAtMs: number
    /** The CDN hosts. */
    hosts: WaMediaHost[]
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
 * Parses a duration the server sent.
 *
 * The server sends either a relative number of seconds or an absolute unix
 * timestamp, the same way it does for the `ttl` of the other connections.
 *
 * @param value The attribute value.
 * @param nowMs The current time.
 */
function parseDurationMs(value: string | undefined, nowMs: number): number | undefined {
    if (value === undefined) return undefined
    const parsed = Number.parseInt(value, 10)
    if (!Number.isSafeInteger(parsed) || parsed <= 0) return undefined
    return parsed >= 1_000_000_000 ? parsed * 1000 : nowMs + parsed * 1000
}

/**
 * Reads the media types a host supports.
 *
 * The `<upload>` and `<download>` children of a `<host>` element list the
 * media types as child tags. A host that lists none supports every type.
 *
 * @param host The `<host>` node.
 * @param tag The tag of the list (`upload` or `download`).
 */
function parseSupportedTypes(host: BinaryNode, tag: string): string[] | undefined {
    const list = getNodeChildrenByTag(host, tag)
    if (list.length === 0) return undefined
    const types: string[] = []
    for (const entry of list) {
        if (!Array.isArray(entry.content)) continue
        for (const child of entry.content) {
            if (typeof child === 'object' && child.tag) types.push(child.tag)
        }
    }
    return types.length > 0 ? types : undefined
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

    const routesExpiryMs = parseDurationMs(connNode.attrs.ttl, nowMs)
    if (routesExpiryMs === undefined) {
        throw new Error('media_conn response has an invalid ttl')
    }

    // The upload token has its own lifetime. The server omits `auth_ttl` on
    // some deployments, in which case the routes' lifetime is the best
    // available estimate.
    const authExpiryMs =
        parseDurationMs(connNode.attrs.auth_ttl, nowMs) ?? routesExpiryMs

    const hosts: WaMediaHost[] = []
    for (const host of getNodeChildrenByTag(connNode, WA_NODE_TAGS.HOST)) {
        const hostname = host.attrs.hostname
        if (!hostname) continue
        const entry: WaMediaHost = {
            hostname,
            isFallback: host.attrs.type === 'fallback',
        }
        const uploadable = parseSupportedTypes(host, 'upload')
        if (uploadable) entry.uploadable = uploadable
        const downloadable = parseSupportedTypes(host, 'download')
        if (downloadable) entry.downloadable = downloadable
        // A host may carry its own fallback instead of listing one.
        if (host.attrs.fallback_hostname) entry.fallback = host.attrs.fallback_hostname
        hosts.push(entry)
    }
    if (hosts.length === 0) throw new Error('media_conn response contains no hosts')

    return {
        auth,
        expiresAtMs: routesExpiryMs,
        authExpiresAtMs: authExpiryMs,
        authTtlSeconds: Math.max(
            0,
            Math.round((authExpiryMs - nowMs) / 1000),
        ),
        queriedAtMs: nowMs,
        hosts,
    }
}

/**
 * Returns whether a host accepts a media type for an operation.
 *
 * A host that does not list its media types accepts every one of them.
 *
 * @param host The host.
 * @param type The media type.
 * @param operation Whether the host is used for an upload or a download.
 */
export function hostSupportsType(
    host: WaMediaHost,
    type: WaMediaType | undefined,
    operation: 'upload' | 'download',
): boolean {
    if (!type) return true
    const supported = operation === 'upload' ? host.uploadable : host.downloadable
    if (!supported) return true
    return supported.includes(type)
}

/**
 * Picks the host a transfer should go to.
 *
 * The official client picks the first host that supports the media type for
 * the operation and keeps the designated fallback host aside, so it can
 * switch over when the selected one fails.
 *
 * @param conn The media connection.
 * @param type The media type, when it is known.
 * @param operation Whether the host is used for an upload or a download.
 */
export function selectMediaHost(
    conn: WaMediaConn,
    type?: WaMediaType,
    operation: 'upload' | 'download' = 'upload',
): string {
    const matching = conn.hosts.find((host) => hostSupportsType(host, type, operation))
    if (matching) return matching.hostname

    // No host declared support for the type: fall back to the primary host
    // rather than refusing to transfer anything.
    const primary = conn.hosts.find((host) => !host.isFallback)
    return primary?.hostname ?? conn.hosts[0]!.hostname
}

/**
 * Returns the host the official client would switch to when the selected one
 * fails.
 *
 * @param conn The media connection.
 * @param host The host that failed.
 */
export function selectMediaFallbackHost(
    conn: WaMediaConn,
    host: string,
): string | undefined {
    const entry = conn.hosts.find((candidate) => candidate.hostname === host)
    if (entry?.fallback) return entry.fallback
    return conn.hosts.find((candidate) => candidate.isFallback)?.hostname
}

/**
 * Builds the URL an encrypted media file is uploaded to.
 *
 * The official client puts the base64 of the encrypted file's hash into the
 * path and repeats it as the `token` query parameter; the `auth` parameter
 * carries the upload token of the media connection.
 *
 * @param host The CDN host.
 * @param path The upload path (`/mms/image`, …).
 * @param auth The upload token.
 * @param fileEncSha256 The SHA-256 of the encrypted payload.
 * @param mediaId The upload id the CDN correlates the request with.
 */
export function buildMediaUploadUrl(
    host: string,
    path: string,
    auth: string,
    fileEncSha256: Uint8Array,
    mediaId?: number | string,
): string {
    const token = base64UrlEncodePadded(fileEncSha256)
    const query = new URLSearchParams()
    query.set('auth', auth)
    query.set('token', token)
    if (mediaId !== undefined) query.set('media_id', String(mediaId))
    return `https://${host}${path}/${token}?${query.toString()}`
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
    /** The media kind the file was uploaded as. */
    mediaType: WaMediaType
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
 * Generates the id the CDN correlates an upload with.
 *
 * The official client uses a random integer in `[1, 2^53 - 1]`.
 */
export function generateMediaId(): number {
    let value = 0n
    for (const byte of randomBytesOf(8)) value = (value << 8n) | BigInt(byte)
    // The modulo only removes the bias of the 64 random bits; the range
    // stays exactly the one the official client uses.
    return Number((value % BigInt(Number.MAX_SAFE_INTEGER)) + 1n)
}

/**
 * Returns whether the upload token of a media connection has expired.
 *
 * The token is what authorises an upload, so once it is gone the connection
 * cannot be used any more — even when the host routes are still valid.
 *
 * @param conn The media connection.
 * @param nowMs The current time.
 */
export function isMediaConnExpired(conn: WaMediaConn, nowMs = Date.now()): boolean {
    return nowMs >= conn.authExpiresAtMs
}

/**
 * Returns whether a media connection should be refreshed.
 *
 * The official client refreshes a connection once 80% of the upload token's
 * lifetime has passed, so a fresh token is in hand before the old one dies,
 * and refreshes it immediately when the host routes expire.
 *
 * @param conn The media connection.
 * @param nowMs The current time.
 */
export function mediaConnNeedsRefresh(conn: WaMediaConn, nowMs = Date.now()): boolean {
    if (nowMs >= conn.expiresAtMs) return true
    const refreshAtMs = conn.queriedAtMs + Math.floor(conn.authTtlSeconds * 0.8) * 1000
    return nowMs >= refreshAtMs
}

/**
 * Fetches a media connection, caching it until it expires.
 */
export class MediaConnectionCache {
    private conn: WaMediaConn | null = null

    /** The connection that is currently cached, if any. */
    peek(): WaMediaConn | null {
        return this.conn
    }

    /**
     * Returns the current media connection, fetching a new one when the
     * cached one expired.
     *
     * @param options The transfer options.
     */
    async get(options: MediaTransferOptions): Promise<WaMediaConn> {
        const cached = this.conn
        if (cached && !isMediaConnExpired(cached)) {
            // The connection is still usable. Refresh it in the background
            // when it grew stale, so the next transfer already has a fresh
            // token. A failed refresh must not break the transfer that is
            // already under way.
            if (mediaConnNeedsRefresh(cached)) {
                void this.refresh(options).catch(() => undefined)
            }
            return cached
        }
        return this.refresh(options)
    }

    /**
     * Fetches a fresh media connection and caches it.
     *
     * @param options The transfer options.
     */
    async refresh(options: MediaTransferOptions): Promise<WaMediaConn> {
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
        /** The upload id the CDN correlates the request with. */
        mediaId?: number | string
        /** An optional abort signal. */
        signal?: AbortSignal
    },
): Promise<WaMediaUpload> {
    const mediaKey = input.mediaKey ?? randomBytesOf(MEDIA_KEY_LENGTH)

    const encrypted = encryptMedia(input.type, mediaKey, input.data)
    const conn = options.conn ?? (await new MediaConnectionCache().get(options))
    const path = MEDIA_UPLOAD_PATHS[input.type]
    if (!path) throw new Error(`unsupported media type: ${input.type}`)

    const host = selectMediaHost(conn, input.type, 'upload')
    const url = buildMediaUploadUrl(
        host,
        path,
        conn.auth,
        encrypted.fileEncSha256,
        input.mediaId,
    )
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
        mediaType: input.type,
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
    const hosts = options.conn
        ? connDownloadHosts(options.conn, payload.mediaType)
        : (options.hosts ?? DEFAULT_MEDIA_HOSTS)
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

/**
 * Returns the hosts a download should be tried on.
 *
 * The hosts of the media connection come first, because the server may name
 * a CDN that serves the file; the well known hosts are the last resort.
 *
 * @param conn The media connection.
 * @param type The media type.
 */
function connDownloadHosts(conn: WaMediaConn, type: WaMediaType): string[] {
    const hosts = conn.hosts
        .filter((host) => hostSupportsType(host, type, 'download'))
        .map((host) => host.hostname)
    const known = DEFAULT_MEDIA_HOSTS.filter((host) => !hosts.includes(host))
    return [...hosts, ...known]
}
