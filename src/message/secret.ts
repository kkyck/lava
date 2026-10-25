/**
 * The per-message secret.
 *
 * Every message carries a 32-byte `messageSecret`. It is the root of a key
 * hierarchy: poll votes, reactions, edits and other *modifications* of a
 * message derive their own key from it via HKDF, so a modification can be
 * decrypted without revealing the original message.
 *
 * The secret never leaves the encrypted envelope — it travels inside the
 * message body.
 */

import { hkdf, randomBytesOf, utf8 } from '../crypto/primitives.js'

/** The length of a message secret. */
export const WA_MESSAGE_SECRET_BYTES = 32

/** The modification types that derive their own secret. */
export const WA_USE_CASE_SECRET_MODIFICATION_TYPES = Object.freeze({
    POLL_VOTE: 'Poll Vote',
    ENC_REACTION: 'Enc Reaction',
    ENC_COMMENT: 'Enc Comment',
    REPORT_TOKEN: 'Report Token',
    EVENT_RESPONSE: 'Event Response',
    EVENT_EDIT_ENCRYPTED: 'Event Edit',
    MESSAGE_EDIT: 'Message Edit',
    POLL_EDIT_ENCRYPTED: 'Poll Edit',
    POLL_ADD_OPTION: 'Poll Add Option',
} as const)

/**
 * Validates that a message secret is exactly 32 bytes.
 *
 * @param messageSecret The candidate secret.
 * @param context Label used in the error message.
 */
export function assertMessageSecret(
    messageSecret: Uint8Array,
    context = 'message secret',
): Uint8Array {
    if (messageSecret.byteLength !== WA_MESSAGE_SECRET_BYTES) {
        throw new Error(
            `${context} must be ${WA_MESSAGE_SECRET_BYTES} bytes (got ${messageSecret.byteLength})`,
        )
    }
    return messageSecret
}

/**
 * Attaches a fresh message secret to a message body.
 *
 * A body that already carries a secret is returned unchanged.
 *
 * @param message The message body.
 */
export function ensureMessageSecret(message: Record<string, unknown>): Record<string, unknown> {
    const context = message.messageContextInfo as Record<string, unknown> | undefined
    const existing = context?.messageSecret as Uint8Array | undefined
    if (existing && existing.byteLength > 0) return message
    return {
        ...message,
        messageContextInfo: {
            ...(context ?? {}),
            messageSecret: randomBytesOf(WA_MESSAGE_SECRET_BYTES),
        },
    }
}

/** The inputs for {@link createUseCaseSecret}. */
export interface UseCaseSecretInput {
    /** The id of the message being modified. */
    stanzaId: string
    /** The original sender of the parent message. */
    parentMsgOriginalSender: string
    /** The sender of the modification. */
    modificationSender: string
    /** The kind of modification. */
    modificationType: string
    /** The parent message's secret. */
    messageSecret: Uint8Array
}

/**
 * Derives the per-use-case secret.
 *
 * @param input The derivation inputs.
 */
export function createUseCaseSecret(input: UseCaseSecretInput): Uint8Array {
    if (input.stanzaId.trim() === '') {
        throw new Error('stanza id must be a non-empty string')
    }
    if (input.parentMsgOriginalSender.trim() === '') {
        throw new Error('parent message original sender must be a non-empty string')
    }
    if (input.modificationSender.trim() === '') {
        throw new Error('modification sender must be a non-empty string')
    }
    const info = utf8(
        input.stanzaId +
            input.parentMsgOriginalSender +
            input.modificationSender +
            input.modificationType,
    )
    return hkdf(assertMessageSecret(input.messageSecret), null, info, WA_MESSAGE_SECRET_BYTES)
}
