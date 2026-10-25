/**
 * Media message construction.
 *
 * A media message is a protobuf `Message` whose payload field carries the
 * metadata of the uploaded file: the media key, the hashes, the CDN path and
 * the thumbnail. The file itself never travels inside the stanza — it was
 * uploaded to the CDN separately.
 */

import type { MessageContent } from './message.js'
import { unwrapMessage } from './message.js'

/** The media kinds the library can upload and download. */
export type WaMediaType =
    | 'image'
    | 'video'
    | 'audio'
    | 'document'
    | 'sticker'
    | 'gif'
    | 'ptt'
    | 'md-app-state'
    | 'md-msg-hist'

/**
 * The media kinds that end up in a chat message.
 *
 * The app-state and history blobs live on the CDN too, but they are never
 * referenced from a message stanza, so they cannot be sent.
 */
export type WaSendableMediaType = Exclude<WaMediaType, 'md-app-state' | 'md-msg-hist'>

/** The metadata of an uploaded media file. */
export interface MediaMessageOptions {
    /** The CDN URL of the file. */
    url?: string
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
    /** The MIME type of the file. */
    mimetype?: string
    /** The caption that goes with the file. */
    caption?: string
    /** The JPEG thumbnail. */
    jpegThumbnail?: Uint8Array
    /** The PNG thumbnail (stickers). */
    pngThumbnail?: Uint8Array
    /** The width of the file, in pixels. */
    width?: number
    /** The height of the file, in pixels. */
    height?: number
    /** The duration of the file, in seconds. */
    seconds?: number
    /** The file name (documents). */
    fileName?: string
    /** The document title (documents). */
    title?: string
    /** The number of pages (documents). */
    pageCount?: number
    /** Whether the file is a push-to-talk voice note. */
    ptt?: boolean
    /** Whether the video plays as a GIF. */
    gifPlayback?: boolean
    /** Whether the sticker is animated. */
    isAnimated?: boolean
    /** The length of the sticker's first frame. */
    firstFrameLength?: number
}

/** Copies the fields that every media message shares. */
function commonFields(options: MediaMessageOptions): Record<string, unknown> {
    const fields: Record<string, unknown> = {
        mediaKey: options.mediaKey,
        fileSha256: options.fileSha256,
        fileEncSha256: options.fileEncSha256,
        fileLength: options.fileLength,
        directPath: options.directPath,
        mediaKeyTimestamp: options.mediaKeyTimestamp,
    }
    if (options.url !== undefined) fields.url = options.url
    return fields
}

/**
 * Builds an image message.
 *
 * @param options The media metadata.
 */
export function buildImageContent(options: MediaMessageOptions): MessageContent {
    const message: Record<string, unknown> = commonFields(options)
    if (options.mimetype !== undefined) message.mimetype = options.mimetype
    if (options.caption !== undefined) message.caption = options.caption
    if (options.width !== undefined) message.width = options.width
    if (options.height !== undefined) message.height = options.height
    if (options.jpegThumbnail !== undefined) message.jpegThumbnail = options.jpegThumbnail
    return { imageMessage: message }
}

/**
 * Builds a video message.
 *
 * @param options The media metadata.
 */
export function buildVideoContent(options: MediaMessageOptions): MessageContent {
    const message: Record<string, unknown> = commonFields(options)
    if (options.mimetype !== undefined) message.mimetype = options.mimetype
    if (options.caption !== undefined) message.caption = options.caption
    if (options.width !== undefined) message.width = options.width
    if (options.height !== undefined) message.height = options.height
    if (options.seconds !== undefined) message.seconds = options.seconds
    if (options.gifPlayback !== undefined) message.gifPlayback = options.gifPlayback
    if (options.jpegThumbnail !== undefined) message.jpegThumbnail = options.jpegThumbnail
    return { videoMessage: message }
}

/**
 * Builds an audio message.
 *
 * @param options The media metadata.
 */
export function buildAudioContent(options: MediaMessageOptions): MessageContent {
    const message: Record<string, unknown> = commonFields(options)
    if (options.mimetype !== undefined) message.mimetype = options.mimetype
    if (options.seconds !== undefined) message.seconds = options.seconds
    if (options.ptt !== undefined) message.ptt = options.ptt
    return { audioMessage: message }
}

/**
 * Builds a document message.
 *
 * @param options The media metadata.
 */
export function buildDocumentContent(options: MediaMessageOptions): MessageContent {
    const message: Record<string, unknown> = commonFields(options)
    if (options.mimetype !== undefined) message.mimetype = options.mimetype
    if (options.caption !== undefined) message.caption = options.caption
    if (options.fileName !== undefined) message.fileName = options.fileName
    if (options.title !== undefined) message.title = options.title
    if (options.pageCount !== undefined) message.pageCount = options.pageCount
    if (options.jpegThumbnail !== undefined) message.jpegThumbnail = options.jpegThumbnail
    return { documentMessage: message }
}

/**
 * Builds a sticker message.
 *
 * @param options The media metadata.
 */
export function buildStickerContent(options: MediaMessageOptions): MessageContent {
    const message: Record<string, unknown> = commonFields(options)
    if (options.mimetype !== undefined) message.mimetype = options.mimetype
    if (options.width !== undefined) message.width = options.width
    if (options.height !== undefined) message.height = options.height
    if (options.isAnimated !== undefined) message.isAnimated = options.isAnimated
    if (options.firstFrameLength !== undefined) message.firstFrameLength = options.firstFrameLength
    if (options.pngThumbnail !== undefined) message.pngThumbnail = options.pngThumbnail
    return { stickerMessage: message }
}

/**
 * Builds the media message that matches a media kind.
 *
 * A GIF is a video message that plays in a loop, and a push-to-talk voice
 * note is an audio message — so those two kinds only change the upload, not
 * the shape of the message.
 *
 * @param type The media kind.
 * @param options The media metadata.
 */
export function buildMediaContent(
    type: WaMediaType,
    options: MediaMessageOptions,
): MessageContent {
    switch (type) {
        case 'image':
            return buildImageContent(options)
        case 'video':
        case 'gif':
            return buildVideoContent(
                type === 'gif' ? { ...options, gifPlayback: true } : options,
            )
        case 'audio':
        case 'ptt':
            return buildAudioContent({ ...options, ptt: type === 'ptt' })
        case 'document':
            return buildDocumentContent(options)
        case 'sticker':
            return buildStickerContent(options)
        default:
            throw new Error(`unsupported media type: ${String(type)}`)
    }
}

/** The media payload of a message. */
export interface MediaPayload {
    /** The media kind. */
    mediaType: WaMediaType
    /** The path the CDN serves the file under. */
    directPath: string
    /** The media key the file was encrypted with. */
    mediaKey: Uint8Array
    /** The SHA-256 of the plaintext. */
    fileSha256?: Uint8Array
    /** The SHA-256 of the encrypted payload. */
    fileEncSha256?: Uint8Array
    /** The MIME type of the file. */
    mimetype?: string
    /** The length of the plaintext. */
    fileLength?: number
    /** The caption that goes with the file. */
    caption?: string
}

/**
 * Extracts the downloadable media metadata from a message.
 *
 * The ephemeral, view-once and document-with-caption envelopes are unwrapped
 * first, so a media message is found wherever it hides.
 *
 * @param message The message body.
 * @returns The payload, or `undefined` when the message carries no media.
 */
export function resolveMediaPayload(message: MessageContent | undefined): MediaPayload | undefined {
    if (!message) return undefined
    const unwrapped = unwrapMessage(message) as Record<string, unknown>

    const build = (
        mediaType: MediaPayload['mediaType'],
        fields: Record<string, unknown> | undefined,
    ): MediaPayload | undefined => {
        if (!fields) return undefined
        const directPath = typeof fields.directPath === 'string' ? fields.directPath : ''
        const mediaKey = fields.mediaKey
        if (!directPath || !(mediaKey instanceof Uint8Array)) return undefined
        const payload: MediaPayload = {
            mediaType,
            directPath,
            mediaKey,
        }
        if (fields.fileSha256 instanceof Uint8Array) payload.fileSha256 = fields.fileSha256
        if (fields.fileEncSha256 instanceof Uint8Array) payload.fileEncSha256 = fields.fileEncSha256
        if (typeof fields.mimetype === 'string') payload.mimetype = fields.mimetype
        if (typeof fields.fileLength === 'number') payload.fileLength = fields.fileLength
        if (typeof fields.caption === 'string') payload.caption = fields.caption
        return payload
    }

    const image = build('image', unwrapped.imageMessage as Record<string, unknown> | undefined)
    if (image) return image

    const video = unwrapped.videoMessage as Record<string, unknown> | undefined
    if (video) {
        const payload = build(video.gifPlayback === true ? 'gif' : 'video', video)
        if (payload) return payload
    }

    const audio = unwrapped.audioMessage as Record<string, unknown> | undefined
    if (audio) {
        const payload = build(audio.ptt === true ? 'ptt' : 'audio', audio)
        if (payload) return payload
    }

    const document = build('document', unwrapped.documentMessage as Record<string, unknown> | undefined)
    if (document) return document

    const sticker = build('sticker', unwrapped.stickerMessage as Record<string, unknown> | undefined)
    if (sticker) return sticker

    return undefined
}
