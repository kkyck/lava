/**
 * WhatsApp node protocol constants.
 *
 * The canonical definitions live in {@link ../../protocol/constants.ts}; this
 * module re-exports them so the node layer can be imported without reaching
 * into the protocol package.
 */

export {
    WA_ADDRESSING_MODES,
    WA_CALL_NODE_ATTRS,
    WA_CALL_PAYLOAD_TAGS,
    WA_CHATSTATE_MEDIA,
    WA_DEFAULTS,
    WA_ENC_CIPHERTEXT_TYPES,
    WA_ENC_MEDIA_TYPES,
    WA_IQ_TYPES,
    WA_MESSAGE_TAGS,
    WA_MESSAGE_TYPES,
    WA_NODE_TAGS,
    WA_PRESENCE_TYPES,
    WA_PRIVACY_VALUES,
    WA_STANZA_MSG_TYPES,
    WA_XMLNS,
} from '../../protocol/constants.js'

export {
    BROADCAST_SERVER,
    GROUP_SERVER,
    HOST_DOMAIN,
    LID_SERVER,
    NEWSLETTER_SERVER,
} from '../../protocol/jid.js'
