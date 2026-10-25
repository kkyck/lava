/**
 * Media tests.
 *
 * The media path is the one that leaves the device: a file is encrypted with
 * a per-file key, uploaded to the WhatsApp CDN and referenced from the
 * message stanza. The tests below pin down the parts that must not drift —
 * the key derivation, the MAC, the CDN handshake and the shape of the
 * message.
 */

import assert from 'node:assert/strict'
import { hkdfSync } from 'node:crypto'
import { describe, it } from 'node:test'

import {
    MEDIA_HKDF_INFO,
    decryptMedia,
    deriveMediaKeys,
    encryptMedia,
    encryptedMediaLength,
    getMediaHkdfInfo,
} from '../src/media/crypto.js'
import {
    DEFAULT_MEDIA_HOSTS,
    buildMediaConnIq,
    buildMediaUploadUrl,
    downloadMedia,
    parseMediaConnResponse,
    selectMediaHost,
    uploadMedia,
    type MediaHttpRequest,
    type MediaHttpResponse,
} from '../src/media/transfer.js'
import {
    buildMediaContent,
    resolveMediaPayload,
} from '../src/protocol/media.js'
import type { BinaryNode } from '../src/transport/binary/types.js'
import { base64UrlEncode } from '../src/util/base64.js'

/** A 32-byte media key. */
const MEDIA_KEY = new Uint8Array(32).fill(7)

/** Builds a media connection response the way the server answers. */
function mediaConnResponse(): BinaryNode {
    return {
        tag: 'iq',
        attrs: { id: 'mc-1', type: 'result' },
        content: [
            {
                tag: 'media_conn',
                attrs: { auth: 'token-abc', ttl: '3600' },
                content: [
                    { tag: 'host', attrs: { hostname: 'mmg.whatsapp.net' } },
                    {
                        tag: 'host',
                        attrs: { hostname: 'mmg-fallback.whatsapp.net', type: 'fallback' },
                    },
                ],
            },
        ],
    }
}

/** Answers a media connection IQ. */
async function answerMediaConn(): Promise<BinaryNode> {
    return mediaConnResponse()
}

describe('media crypto', () => {
    it('derives the keys the way the official client does', () => {
        const expected = new Uint8Array(
            hkdfSync('sha256', MEDIA_KEY, Buffer.alloc(0), Buffer.from('WhatsApp Image Keys'), 80),
        )
        const keys = deriveMediaKeys('image', MEDIA_KEY)
        assert.deepEqual(keys.iv, expected.subarray(0, 16))
        assert.deepEqual(keys.encKey, expected.subarray(16, 48))
        assert.deepEqual(keys.macKey, expected.subarray(48, 80))
    })

    it('uses the same key context for the media kinds that share one', () => {
        assert.deepEqual(getMediaHkdfInfo('image'), getMediaHkdfInfo('sticker'))
        assert.deepEqual(getMediaHkdfInfo('video'), getMediaHkdfInfo('gif'))
        assert.deepEqual(getMediaHkdfInfo('audio'), getMediaHkdfInfo('ptt'))
        assert.notDeepEqual(getMediaHkdfInfo('image'), getMediaHkdfInfo('video'))
        assert.notDeepEqual(getMediaHkdfInfo('video'), getMediaHkdfInfo('document'))
    })

    it('rejects an unsupported media kind', () => {
        assert.throws(() => getMediaHkdfInfo('nope'), /unsupported media type/)
    })

    it('rejects a media key of the wrong length', () => {
        assert.throws(() => deriveMediaKeys('image', new Uint8Array(16)), /invalid media key length/)
    })

    it('encrypts and decrypts a payload', () => {
        const plaintext = new TextEncoder().encode('hello media')
        const encrypted = encryptMedia('image', MEDIA_KEY, plaintext)

        // The ciphertext is the padded plaintext plus the truncated MAC.
        assert.equal(
            encrypted.ciphertextHmac.length,
            encryptedMediaLength(plaintext.length),
        )
        assert.equal(encrypted.fileSha256.length, 32)
        assert.equal(encrypted.fileEncSha256.length, 32)
        assert.equal(encrypted.plaintextLength, plaintext.length)

        const decrypted = decryptMedia(
            'image',
            MEDIA_KEY,
            encrypted.ciphertextHmac,
            encrypted.fileSha256,
            encrypted.fileEncSha256,
        )
        assert.deepEqual(decrypted.plaintext, plaintext)
    })

    it('never leaks the plaintext into the ciphertext', () => {
        const plaintext = new Uint8Array(64).fill(0xab)
        const encrypted = encryptMedia('image', MEDIA_KEY, plaintext)
        assert.equal(
            encrypted.ciphertextHmac.some((byte) => byte === 0xab),
            false,
        )
    })

    it('rejects a payload whose MAC was tampered with', () => {
        const encrypted = encryptMedia('image', MEDIA_KEY, new Uint8Array(32))
        encrypted.ciphertextHmac[0] = encrypted.ciphertextHmac[0]! ^ 0xff
        assert.throws(
            () => decryptMedia('image', MEDIA_KEY, encrypted.ciphertextHmac),
            /MAC mismatch/,
        )
    })

    it('rejects a payload whose encrypted hash does not match', () => {
        const encrypted = encryptMedia('image', MEDIA_KEY, new Uint8Array(32))
        const wrong = new Uint8Array(encrypted.fileEncSha256)
        wrong[0] = wrong[0]! ^ 0xff
        assert.throws(
            () =>
                decryptMedia(
                    'image',
                    MEDIA_KEY,
                    encrypted.ciphertextHmac,
                    undefined,
                    wrong,
                ),
            /encrypted hash mismatch/,
        )
    })

    it('rejects a payload whose plaintext hash does not match', () => {
        const encrypted = encryptMedia('image', MEDIA_KEY, new Uint8Array(32))
        const wrong = new Uint8Array(encrypted.fileSha256)
        wrong[0] = wrong[0]! ^ 0xff
        assert.throws(
            () =>
                decryptMedia(
                    'image',
                    MEDIA_KEY,
                    encrypted.ciphertextHmac,
                    wrong,
                    encrypted.fileEncSha256,
                ),
            /plaintext hash mismatch/,
        )
    })

    it('rejects a payload that is too short', () => {
        assert.throws(
            () => decryptMedia('image', MEDIA_KEY, new Uint8Array(4)),
            /too short/,
        )
    })

    it('computes the encrypted length the way the cipher does', () => {
        assert.equal(encryptedMediaLength(0), 16 + 10)
        assert.equal(encryptedMediaLength(15), 16 + 10)
        assert.equal(encryptedMediaLength(16), 32 + 10)
        assert.equal(encryptedMediaLength(17), 32 + 10)
        assert.throws(() => encryptedMediaLength(-1), /invalid plaintext length/)
    })

    it('knows every media kind it derives keys for', () => {
        for (const kind of Object.keys(MEDIA_HKDF_INFO)) {
            assert.equal(getMediaHkdfInfo(kind).length > 0, true)
        }
    })
})

describe('media transfer', () => {
    it('builds the media connection IQ the way the official client does', () => {
        const iq = buildMediaConnIq()
        assert.equal(iq.tag, 'iq')
        assert.equal(iq.attrs.type, 'set')
        assert.equal(iq.attrs.xmlns, 'w:m')
        assert.equal(iq.attrs.to, 's.whatsapp.net')
        const content = iq.content as BinaryNode[]
        assert.equal(content.length, 1)
        assert.equal(content[0]?.tag, 'media_conn')
    })

    it('parses the media connection the server answers with', () => {
        const conn = parseMediaConnResponse(mediaConnResponse(), 1_000_000)
        assert.equal(conn.auth, 'token-abc')
        assert.equal(conn.hosts.length, 2)
        assert.equal(conn.hosts[0]?.hostname, 'mmg.whatsapp.net')
        assert.equal(conn.hosts[0]?.isFallback, false)
        assert.equal(conn.hosts[1]?.isFallback, true)
        // A ttl of 3600 seconds is an hour from now.
        assert.equal(conn.expiresAtMs, 1_000_000 + 3_600_000)
    })

    it('rejects a media connection without an auth token', () => {
        const response = mediaConnResponse()
        const conn = response.content as BinaryNode[]
        delete conn[0]!.attrs.auth
        assert.throws(() => parseMediaConnResponse(response), /missing auth/)
    })

    it('rejects a media connection without hosts', () => {
        const response = mediaConnResponse()
        const conn = response.content as BinaryNode[]
        conn[0]!.content = []
        assert.throws(() => parseMediaConnResponse(response), /no hosts/)
    })

    it('prefers the primary host', () => {
        const conn = parseMediaConnResponse(mediaConnResponse())
        assert.equal(selectMediaHost(conn), 'mmg.whatsapp.net')
    })

    it('builds the upload URL the way the CDN expects it', () => {
        const hash = new Uint8Array(32).fill(1)
        const url = buildMediaUploadUrl('mmg.whatsapp.net', '/mms/image', 'tok en', hash)
        const token = base64UrlEncode(hash)
        assert.ok(url.startsWith(`https://mmg.whatsapp.net/mms/image/${token}?`))
        assert.ok(url.includes('auth=tok%20en'))
        assert.ok(url.includes(`token=${encodeURIComponent(token)}`))
    })

    it('uploads an encrypted file and parses the CDN answer', async () => {
        const requests: MediaHttpRequest[] = []
        const plaintext = new TextEncoder().encode('the picture')

        const upload = await uploadMedia(
            {
                query: answerMediaConn,
                http: async (request) => {
                    requests.push(request)
                    return {
                        status: 200,
                        headers: {},
                        body: new TextEncoder().encode(
                            JSON.stringify({
                                url: 'https://mmg.whatsapp.net/v/t62.7117-24/1',
                                direct_path: '/v/t62.7117-24/1',
                            }),
                        ),
                    }
                },
            },
            { data: plaintext, type: 'image', mimetype: 'image/jpeg' },
        )

        // The media connection was fetched first.
        assert.equal(requests.length, 1)
        assert.equal(requests[0]!.method, 'POST')
        assert.equal(requests[0]!.headers['content-type'], 'image/jpeg')
        assert.ok(requests[0]!.url.includes('/mms/image/'))
        assert.ok(requests[0]!.url.includes('auth=token-abc'))

        // The body is the encrypted payload, not the plaintext.
        assert.notDeepEqual(requests[0]!.body, plaintext)
        assert.equal(
            requests[0]!.body?.length,
            encryptedMediaLength(plaintext.length),
        )

        // The result carries everything the message stanza needs.
        assert.equal(upload.directPath, '/v/t62.7117-24/1')
        assert.equal(upload.url, 'https://mmg.whatsapp.net/v/t62.7117-24/1')
        assert.equal(upload.mediaKey.length, 32)
        assert.equal(upload.fileLength, plaintext.length)
        assert.equal(upload.fileSha256.length, 32)
        assert.equal(upload.fileEncSha256.length, 32)

        // And the CDN can hand the very same bytes back.
        const downloaded = await downloadMedia(
            {
                query: answerMediaConn,
                http: async () => ({
                    status: 200,
                    headers: {},
                    body: requests[0]!.body!,
                }),
            },
            {
                mediaType: 'image',
                directPath: upload.directPath,
                mediaKey: upload.mediaKey,
                fileSha256: upload.fileSha256,
                fileEncSha256: upload.fileEncSha256,
            },
        )
        assert.deepEqual(downloaded, plaintext)
    })

    it('falls back to the next host when a download fails', async () => {
        const attempted: string[] = []
        const plaintext = new TextEncoder().encode('fallback')
        const encrypted = encryptMedia('image', MEDIA_KEY, plaintext)

        const downloaded = await downloadMedia(
            {
                query: answerMediaConn,
                hosts: DEFAULT_MEDIA_HOSTS,
                http: async (request) => {
                    attempted.push(new URL(request.url).host)
                    if (attempted.length === 1) {
                        return { status: 500, headers: {}, body: new Uint8Array(0) }
                    }
                    return {
                        status: 200,
                        headers: {},
                        body: encrypted.ciphertextHmac,
                    }
                },
            },
            {
                mediaType: 'image',
                directPath: '/v/t62.7117-24/9',
                mediaKey: MEDIA_KEY,
                fileSha256: encrypted.fileSha256,
                fileEncSha256: encrypted.fileEncSha256,
            },
        )

        assert.deepEqual(attempted, [...DEFAULT_MEDIA_HOSTS])
        assert.deepEqual(downloaded, plaintext)
    })

    it('reports a failed upload', async () => {
        await assert.rejects(
            () =>
                uploadMedia(
                    {
                        query: answerMediaConn,
                        http: async () => ({
                            status: 500,
                            headers: {},
                            body: new Uint8Array(0),
                        }),
                    },
                    { data: new Uint8Array(4), type: 'image', mimetype: 'image/jpeg' },
                ),
            /status 500/,
        )
    })

    it('reports an upload answer without a path', async () => {
        await assert.rejects(
            () =>
                uploadMedia(
                    {
                        query: answerMediaConn,
                        http: async () => ({
                            status: 200,
                            headers: {},
                            body: new TextEncoder().encode('{}'),
                        }),
                    },
                    { data: new Uint8Array(4), type: 'image', mimetype: 'image/jpeg' },
                ),
            /missing url\/direct_path/,
        )
    })
})

describe('media messages', () => {
    /** The metadata a media message carries. */
    const metadata = {
        directPath: '/v/t62.7117-24/1',
        mediaKey: MEDIA_KEY,
        fileSha256: new Uint8Array(32).fill(1),
        fileEncSha256: new Uint8Array(32).fill(2),
        fileLength: 1024,
        mediaKeyTimestamp: 1_700_000_000,
    }

    it('builds an image message', () => {
        const body = buildMediaContent('image', {
            ...metadata,
            mimetype: 'image/jpeg',
            caption: 'look',
            width: 100,
            height: 50,
        })
        const image = body.imageMessage as Record<string, unknown>
        assert.equal(image.mimetype, 'image/jpeg')
        assert.equal(image.caption, 'look')
        assert.equal(image.width, 100)
        assert.equal(image.height, 50)
        assert.equal(image.fileLength, 1024)
        assert.equal(image.directPath, '/v/t62.7117-24/1')
        assert.deepEqual(image.mediaKey, MEDIA_KEY)
    })

    it('builds a video message', () => {
        const body = buildMediaContent('video', {
            ...metadata,
            mimetype: 'video/mp4',
            seconds: 12,
        })
        const video = body.videoMessage as Record<string, unknown>
        assert.equal(video.seconds, 12)
        assert.equal(video.gifPlayback, undefined)
    })

    it('builds a GIF as a looping video', () => {
        const body = buildMediaContent('gif', { ...metadata, mimetype: 'video/mp4' })
        const video = body.videoMessage as Record<string, unknown>
        assert.equal(video.gifPlayback, true)
    })

    it('builds a voice note as a push-to-talk audio message', () => {
        const body = buildMediaContent('ptt', { ...metadata, mimetype: 'audio/ogg' })
        const audio = body.audioMessage as Record<string, unknown>
        assert.equal(audio.ptt, true)
    })

    it('builds a document message', () => {
        const body = buildMediaContent('document', {
            ...metadata,
            mimetype: 'application/pdf',
            fileName: 'invoice.pdf',
            title: 'Invoice',
            pageCount: 3,
        })
        const document = body.documentMessage as Record<string, unknown>
        assert.equal(document.fileName, 'invoice.pdf')
        assert.equal(document.title, 'Invoice')
        assert.equal(document.pageCount, 3)
    })

    it('builds a sticker message', () => {
        const body = buildMediaContent('sticker', {
            ...metadata,
            mimetype: 'image/webp',
            isAnimated: true,
            firstFrameLength: 2048,
        })
        const sticker = body.stickerMessage as Record<string, unknown>
        assert.equal(sticker.isAnimated, true)
        assert.equal(sticker.firstFrameLength, 2048)
    })

    it('extracts the media payload of a message', () => {
        const body = buildMediaContent('image', { ...metadata, mimetype: 'image/jpeg' })
        const payload = resolveMediaPayload(body)
        assert.ok(payload)
        assert.equal(payload.mediaType, 'image')
        assert.equal(payload.directPath, '/v/t62.7117-24/1')
        assert.deepEqual(payload.mediaKey, MEDIA_KEY)
        assert.equal(payload.mimetype, 'image/jpeg')
    })

    it('unwraps the envelope a media message hides in', () => {
        const inner = buildMediaContent('image', { ...metadata, mimetype: 'image/jpeg' })
        const payload = resolveMediaPayload({ ephemeralMessage: { message: inner } })
        assert.ok(payload)
        assert.equal(payload.mediaType, 'image')
    })

    it('reports the media kind of a GIF and of a voice note', () => {
        const gif = resolveMediaPayload(
            buildMediaContent('gif', { ...metadata, mimetype: 'video/mp4' }),
        )
        assert.equal(gif?.mediaType, 'gif')

        const ptt = resolveMediaPayload(
            buildMediaContent('ptt', { ...metadata, mimetype: 'audio/ogg' }),
        )
        assert.equal(ptt?.mediaType, 'ptt')
    })

    it('finds no payload in a text message', () => {
        assert.equal(resolveMediaPayload({ conversation: 'hi' }), undefined)
        assert.equal(resolveMediaPayload(undefined), undefined)
    })
})
